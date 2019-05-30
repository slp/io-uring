// Copyright 2019 Red Hat, Inc. All Rights Reserved.
// SPDX-License-Identifier: LGPL-2.1-only

//! This crate provides a wrapper around liburing-sys providing a safe
//! and simple way for creating a io_uring instance, registering an eventfd
//! file descriptor for receiving completion notifications, submitting read
//! and write requests, and checking for completions.
//!
//! # Usage
//!
//! ## Requirements
//!
//! This crate requires a kernel with io_uring support. This means 5.1 or
//! higher. Support for registering an eventfd for receiving completion
//! notifications requires 5.2 or higher.
//!
//! ## Unaligned buffers
//!
//! Under certain circumstances, io_uring may require the buffer holding the
//! data for a write operation, or used to store the data for a read request,
//! to be page-aligned.
//!
//! This crate checks the buffer alignment, and it either passes it directly
//! to the kernel (if page aligned), or uses a temporary self-allocated buffer
//! for the operation (if not page aligned), copying in/out the data between
//! both buffers as required.
//!
//! This behavior allows users of this crate to avoid worrying about buffer
//! alignment themselves, but this comes with a cost (one additional copy plus
//! the cost of allocating and freeing the temporary buffer). Users desiring
//! to obtain the best possible performance need to make sure their buffers
//! are aligned before using them to submit read/write requests to UringQueue.
//!
//! ## Example
//!
//! ```
//! use io_uring::{Error, UringQueue};
//! use std::fs::File;
//! use std::io;
//! use std::os::unix::io::AsRawFd;
//!
//! fn read_exact(file: File, buf: &mut [u8], offset: i64, wait: bool) -> Result<(), Error> {
//!     let mut queue = UringQueue::new(128)?;
//!     let cookie: u64 = 1234;
//!
//!     queue.submit_read(file.as_raw_fd(), buf, offset, cookie)?;
//!     match queue.get_completion(wait)? {
//!         Some(c) => {
//!             assert!(c == cookie);
//!             println!("Successfully read from file: buf={:?}", buf);
//!             Ok(())
//!         }
//!         None => {
//!             assert!(!wait);
//!             Err(Error::IOError(io::Error::new(
//!                 io::ErrorKind::WouldBlock,
//!                 "completion queue was empty and wait == false",
//!             )))
//!         }
//!     }
//! }
//!```

#![deny(missing_docs)]

use core::cell::Cell;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

use libc;
use liburing_sys::{
    io_uring, io_uring_cqe, io_uring_cqe_seen, io_uring_get_sqe, io_uring_peek_cqe,
    io_uring_prep_readv, io_uring_prep_writev, io_uring_queue_exit, io_uring_queue_init,
    io_uring_register, io_uring_submit, io_uring_wait_cqe,
};

/// Register an eventfd in the uring for completion notifications.
pub const IORING_REGISTER_EVENTFD: u32 = 4;
/// Unregister a previously registered eventfd.
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;

#[derive(PartialEq)]
enum RequestType {
    Read,
    Write,
}

#[repr(C)]
struct UringRequest {
    iov: libc::iovec,
    fd: RawFd,
    offset: i64,
    client_iov: libc::iovec,
    client_cookie: u64,
    self_allocated: bool,
    request_type: RequestType,
}

/// Errors from UringQueue operations.
#[derive(Debug)]
pub enum Error {
    /// Can't initialize the underlying io_ring queue.
    CantInitializeQueue(io::Error),
    /// Can't register a EventFd with the io_ring queue.
    CantRegisterEventFd(io::Error),
    /// Can't allocate a temporary aligned buffer for the request.
    CantAllocateAlignedBuffer(io::Error),
    /// Can't submit the request to the io_ring queue.
    CantSubmitRequest(io::Error),
    /// Can't check the io_ring completion queue.
    CantCheckCompletionQueue(io::Error),
    /// The request failed to complete.
    IOError(io::Error),
}

/// UringQueue provides safe access to io_uring features.
pub struct UringQueue {
    ring: io_uring,
    page_size: usize,
}

impl UringQueue {
    /// Create a new UringQueue with a fixed queue depth.
    pub fn new(queue_depth: u32) -> Result<Self, Error> {
        let mut ring: io_uring = unsafe { mem::uninitialized() };
        let ret = unsafe { io_uring_queue_init(queue_depth, &mut ring, 0) };

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        if ret < 0 {
            Err(Error::CantInitializeQueue(io::Error::from_raw_os_error(
                ret,
            )))
        } else {
            Ok(UringQueue { ring, page_size })
        }
    }

    /// Register an eventfd with the underlying io_uring to be notified when
    /// there's a pending completion in the queue.
    pub fn register_eventfd(&mut self, efd: RawFd) -> Result<(), Error> {
        let ret = unsafe {
            io_uring_register(
                self.ring.ring_fd,
                IORING_REGISTER_EVENTFD,
                Cell::new(efd).as_ptr() as *mut i32 as *mut core::ffi::c_void,
                1,
            )
        };

        if ret < 0 {
            Err(Error::CantRegisterEventFd(io::Error::from_raw_os_error(
                ret,
            )))
        } else {
            Ok(())
        }
    }

    unsafe fn prepare_request(
        &self,
        fd: RawFd,
        buf_ptr: usize,
        buf_len: usize,
        offset: i64,
        cookie: u64,
        request_type: RequestType,
    ) -> Result<*mut UringRequest, Error> {
        let req_ptr = libc::malloc(mem::size_of::<UringRequest>());
        let mut req = req_ptr as *mut UringRequest;

        if buf_ptr % self.page_size == 0 {
            // Our caller is making things easy by providing us an aligned buffer.
            (*req).iov.iov_base = buf_ptr as *mut core::ffi::c_void;
            (*req).iov.iov_len = buf_len;
            (*req).self_allocated = false;
        } else {
            // Caller gave us an unaligned buffer, so we need to allocate one ourselves.
            let mut aligned_buf = mem::uninitialized();
            let ret = libc::posix_memalign(&mut aligned_buf, self.page_size, buf_len);
            if ret != 0 {
                return Err(Error::CantAllocateAlignedBuffer(
                    io::Error::from_raw_os_error(ret),
                ));
            }

            if request_type == RequestType::Write {
                libc::memcpy(aligned_buf, buf_ptr as *mut core::ffi::c_void, buf_len);
            }

            (*req).client_iov.iov_base = buf_ptr as *mut core::ffi::c_void;
            (*req).client_iov.iov_len = buf_len;
            (*req).iov.iov_base = aligned_buf;
            (*req).iov.iov_len = buf_len;
            (*req).fd = fd;
            (*req).offset = offset;
            (*req).self_allocated = true;
        }

        (*req).client_cookie = cookie;
        (*req).request_type = request_type;
        Ok(req)
    }

    /// Submit a request for reading from `fd`, starting at `offset`, and storing the
    /// result in `buf`. `cookie` is an arbitrary u64 value that can be used to keep
    /// track of the request.
    pub fn submit_read(
        &mut self,
        fd: RawFd,
        buf: &mut [u8],
        offset: i64,
        cookie: u64,
    ) -> Result<(), Error> {
        let req = unsafe {
            self.prepare_request(
                fd,
                buf.as_ptr() as usize,
                buf.len(),
                offset,
                cookie,
                RequestType::Read,
            )?
        };

        let sqe = unsafe { io_uring_get_sqe(&mut self.ring) };
        if sqe == std::ptr::null_mut() {
            panic!("can't get sqe");
        }

        unsafe { io_uring_prep_readv(sqe, fd, &mut (*req).iov, 1, offset) };
        unsafe { (*sqe).user_data = req as u64 };

        let ret = unsafe { io_uring_submit(&mut self.ring) };
        if ret < 0 {
            return Err(Error::CantSubmitRequest(io::Error::from_raw_os_error(ret)));
        }

        Ok(())
    }

    /// Submit a request for writing the contents of `buf` to `fd`, starting at
    /// `offset`. `cookie` is an arbitrary u64 value that can be used to keep
    /// track of the request.
    pub fn submit_write(
        &mut self,
        fd: RawFd,
        buf: &[u8],
        offset: i64,
        cookie: u64,
    ) -> Result<(), Error> {
        let req = unsafe {
            self.prepare_request(
                fd,
                buf.as_ptr() as usize,
                buf.len(),
                offset,
                cookie,
                RequestType::Write,
            )?
        };

        let sqe = unsafe { io_uring_get_sqe(&mut self.ring) };
        if sqe == std::ptr::null_mut() {
            panic!("can't get sqe");
        }

        unsafe { io_uring_prep_writev(sqe, fd, &mut (*req).iov, 1, offset) };
        unsafe { (*sqe).user_data = req as u64 };

        let ret = unsafe { io_uring_submit(&mut self.ring) };
        if ret < 0 {
            return Err(Error::CantSubmitRequest(io::Error::from_raw_os_error(ret)));
        }

        Ok(())
    }

    /// Check the completion queue and, if there's completion available to be
    /// retrieved, process it and return the u64 value specified as `cookie`
    /// in the request.
    ///
    /// If there are no completions available in the queue and `wait` is
    /// `true`, keep waiting until there's a completion available, otherwise
    /// return `None`.
    pub fn get_completion(&mut self, wait: bool) -> Result<Option<u64>, Error> {
        let mut cqe: *mut io_uring_cqe = unsafe { std::mem::zeroed() };
        let ret;

        if wait {
            ret = unsafe { io_uring_wait_cqe(&mut self.ring, &mut cqe) };
        } else {
            ret = unsafe { io_uring_peek_cqe(&mut self.ring, &mut cqe) };
        }
        if ret < 0 {
            return Err(Error::CantCheckCompletionQueue(
                io::Error::from_raw_os_error(ret),
            ));
        }
        if cqe.is_null() {
            return Ok(None);
        }

        let mut req = unsafe { &mut *((*cqe).user_data as *mut UringRequest) };

        unsafe {
            if (*cqe).res < 0 {
                return Err(Error::IOError(io::Error::from_raw_os_error((*cqe).res)));
            } else if ((*cqe).res as usize) < req.iov.iov_len {
                // We've got a partial read/write. Adjust base and len, and queue again.
                req.iov.iov_base =
                    ((req.iov.iov_base as usize) + (*cqe).res as usize) as *mut core::ffi::c_void;
                req.iov.iov_len -= (*cqe).res as usize;

                let sqe = io_uring_get_sqe(&mut self.ring);
                if sqe == std::ptr::null_mut() {
                    panic!("can't get sqe");
                }

                match req.request_type {
                    RequestType::Read => {
                        io_uring_prep_readv(sqe, req.fd, &mut req.iov, 1, req.offset)
                    }
                    RequestType::Write => {
                        io_uring_prep_writev(sqe, req.fd, &mut req.iov, 1, req.offset)
                    }
                };

                (*sqe).user_data = req as *const _ as u64;

                if !wait {
                    return Ok(None);
                } else {
                    return self.get_completion(wait);
                }
            }
        }

        if req.self_allocated {
            if req.request_type == RequestType::Read {
                unsafe {
                    libc::memcpy(
                        req.client_iov.iov_base,
                        req.iov.iov_base,
                        req.client_iov.iov_len,
                    )
                };
            }

            unsafe { libc::free(req.iov.iov_base) };
            unsafe { libc::free(req as *const _ as *mut core::ffi::c_void) };
        }
        unsafe { io_uring_cqe_seen(&mut self.ring, cqe) };
        Ok(Some(req.client_cookie))
    }
}

impl Drop for UringQueue {
    fn drop(&mut self) {
        unsafe { io_uring_queue_exit(&mut self.ring) };
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, UringQueue};
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use tempfile::tempfile;

    fn prepare_test_file() -> Result<File, Error> {
        let mut file = tempfile().unwrap();
        writeln!(file, "Test file").unwrap();
        Ok(file)
    }

    #[test]
    fn create_queue() -> Result<(), Error> {
        let _queue = UringQueue::new(128)?;
        Ok(())
    }

    #[test]
    fn submit_read() -> Result<(), Error> {
        let mut queue = UringQueue::new(128)?;
        let mut buf: [u8; 1] = [0u8];
        let file = prepare_test_file()?;

        queue.submit_read(file.as_raw_fd(), &mut buf[..], 0, 0)?;
        Ok(())
    }

    #[test]
    fn submit_write() -> Result<(), Error> {
        let mut queue = UringQueue::new(128)?;
        let buf: [u8; 1] = [0u8];
        let file = prepare_test_file()?;

        queue.submit_write(file.as_raw_fd(), &buf[..], 0, 0)?;
        Ok(())
    }

    #[test]
    fn submit_read_and_wait_for_completion() -> Result<(), Error> {
        let cookie: u64 = 1234;
        let mut queue = UringQueue::new(128)?;
        let mut buf: [u8; 1] = [0u8];
        let file = prepare_test_file()?;

        queue.submit_read(file.as_raw_fd(), &mut buf[..], 0, cookie)?;
        let completion_cookie_opt = queue.get_completion(true)?;
        assert!(completion_cookie_opt.is_some());
        let completion_cookie = completion_cookie_opt.unwrap();

        assert!(
            completion_cookie == cookie,
            "completion_cookie={} cookie={}",
            completion_cookie,
            cookie
        );
        Ok(())
    }

    #[test]
    fn submit_read_and_peek_for_completion() -> Result<(), Error> {
        let cookie: u64 = 1234;
        let mut queue = UringQueue::new(128)?;
        let mut buf: [u8; 1] = [0u8];
        let file = prepare_test_file()?;

        queue.submit_read(file.as_raw_fd(), &mut buf[..], 0, cookie)?;
        let completion_cookie_opt = queue.get_completion(true)?;
        assert!(completion_cookie_opt.is_some());
        let completion_cookie = completion_cookie_opt.unwrap();
        let completion_cookie_opt = queue.get_completion(false)?;
        assert!(completion_cookie_opt.is_none());

        assert!(
            completion_cookie == cookie,
            "completion_cookie={} cookie={}",
            completion_cookie,
            cookie
        );
        Ok(())
    }

    #[test]
    fn submit_write_and_check_contents() -> Result<(), Error> {
        let wcookie: u64 = 1234;
        let rcookie: u64 = 4321;
        let mut queue = UringQueue::new(128)?;
        let test_str = "write test";
        let mut buf: Vec<u8> = vec![];

        let file = prepare_test_file()?;

        queue.submit_write(file.as_raw_fd(), &test_str.as_bytes(), 0, wcookie)?;
        let completion_cookie_opt = queue.get_completion(true)?;
        assert!(completion_cookie_opt.is_some());
        let completion_cookie = completion_cookie_opt.unwrap();
        assert!(
            completion_cookie == wcookie,
            "completion_cookie={} cookie={}",
            completion_cookie,
            wcookie
        );

        buf.resize_with(test_str.as_bytes().len(), Default::default);
        queue.submit_read(file.as_raw_fd(), &mut buf[..], 0, rcookie)?;
        let completion_cookie_opt = queue.get_completion(true)?;
        assert!(completion_cookie_opt.is_some());
        let completion_cookie = completion_cookie_opt.unwrap();
        assert!(
            completion_cookie == rcookie,
            "completion_cookie={} cookie={}",
            completion_cookie,
            rcookie
        );

        let result_str = std::str::from_utf8(&buf).unwrap();
        assert!(
            result_str == test_str,
            "result_str={}, test_str={}",
            result_str,
            test_str
        );
        Ok(())
    }

}
