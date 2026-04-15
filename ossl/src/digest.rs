// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL digest apis

use std::ffi::{c_uint, CStr};

use crate::bindings::*;

use crate::{cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam};

use native_ossl::digest::{DigestAlg as NativeDigestAlg, DigestCtx as NativeDigestCtx};

/// Wrapper around OpenSSL's `EVP_MD`, managing its lifecycle.
/// Internally backed by `native_ossl::digest::DigestAlg`.
#[derive(Debug)]
pub struct EvpMd(NativeDigestAlg);

/// Methods for creating and accessing `EvpMd`.
impl EvpMd {
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpMd, Error> {
        let alg = NativeDigestAlg::fetch_in(ctx.as_lib_ctx(), name, None)?;
        Ok(EvpMd(alg))
    }

    /// Returns a const pointer to the underlying `EVP_MD`.
    ///
    /// # Safety
    ///
    /// The pointer is valid for the lifetime of this `EvpMd`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD {
        // Cast between two bindgen representations of the same C struct.
        self.0.as_ptr() as *const EVP_MD
    }

    /// Returns a mutable pointer to the underlying `EVP_MD`.
    ///
    /// # Safety
    ///
    /// The pointer is valid for the lifetime of this `EvpMd`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD {
        self.0.as_ptr() as *mut EVP_MD
    }
}

impl Clone for EvpMd {
    fn clone(&self) -> Self {
        EvpMd(self.0.clone())
    }
}

unsafe impl Send for EvpMd {}
unsafe impl Sync for EvpMd {}

/// Wrapper around OpenSSL's `EVP_MD_CTX`, managing its lifecycle.
/// Internally backed by `native_ossl::digest::DigestCtx`.
#[derive(Debug)]
pub struct EvpMdCtx(NativeDigestCtx);

/// Methods for creating and accessing `EvpMdCtx`.
impl EvpMdCtx {
    pub fn new() -> Result<EvpMdCtx, Error> {
        let ptr = unsafe { EVP_MD_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_CTX_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        // SAFETY: ptr is non-null and we transfer ownership to DigestCtx.
        let ctx = unsafe {
            NativeDigestCtx::from_ptr(ptr as *mut _)
        };
        Ok(EvpMdCtx(ctx))
    }

    /// Returns a const pointer to the underlying `EVP_MD_CTX`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD_CTX {
        self.0.as_ptr() as *const EVP_MD_CTX
    }

    /// Returns a mutable pointer to the underlying `EVP_MD_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD_CTX {
        self.0.as_ptr() as *mut EVP_MD_CTX
    }

    /// Tries to clone the context.
    pub fn try_clone(&self) -> Result<EvpMdCtx, Error> {
        Ok(EvpMdCtx(self.0.fork()?))
    }

    #[cfg(ossl_v400)]
    pub fn serialize(&self, state: Option<&mut [u8]>) -> Result<usize, Error> {
        match state {
            None => Ok(self.0.serialize_size()?),
            Some(out) => Ok(self.0.serialize(out)?),
        }
    }

    #[cfg(ossl_v400)]
    pub fn deserialize(&mut self, state: &[u8]) -> Result<(), Error> {
        Ok(self.0.deserialize(state)?)
    }
}

unsafe impl Send for EvpMdCtx {}
unsafe impl Sync for EvpMdCtx {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigestAlg {
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    #[cfg(feature = "rfc9580")]
    Md5,
}

pub(crate) fn digest_to_string(digest: DigestAlg) -> &'static CStr {
    match digest {
        DigestAlg::Sha1 => cstr!(OSSL_DIGEST_NAME_SHA1),
        DigestAlg::Sha2_224 => cstr!(OSSL_DIGEST_NAME_SHA2_224),
        DigestAlg::Sha2_256 => cstr!(OSSL_DIGEST_NAME_SHA2_256),
        DigestAlg::Sha2_384 => cstr!(OSSL_DIGEST_NAME_SHA2_384),
        DigestAlg::Sha2_512 => cstr!(OSSL_DIGEST_NAME_SHA2_512),
        DigestAlg::Sha2_512_224 => cstr!(OSSL_DIGEST_NAME_SHA2_512_224),
        DigestAlg::Sha2_512_256 => cstr!(OSSL_DIGEST_NAME_SHA2_512_256),
        DigestAlg::Sha3_224 => cstr!(OSSL_DIGEST_NAME_SHA3_224),
        DigestAlg::Sha3_256 => cstr!(OSSL_DIGEST_NAME_SHA3_256),
        DigestAlg::Sha3_384 => cstr!(OSSL_DIGEST_NAME_SHA3_384),
        DigestAlg::Sha3_512 => cstr!(OSSL_DIGEST_NAME_SHA3_512),
        #[cfg(feature = "rfc9580")]
        DigestAlg::Md5 => cstr!(OSSL_DIGEST_NAME_MD5),
    }
}

pub(crate) fn string_to_digest(digest: &CStr) -> Result<DigestAlg, Error> {
    match digest.to_bytes() {
        b"SHA1" => Ok(DigestAlg::Sha1),
        b"SHA2-224" => Ok(DigestAlg::Sha2_224),
        b"SHA2-256" => Ok(DigestAlg::Sha2_256),
        b"SHA2-384" => Ok(DigestAlg::Sha2_384),
        b"SHA2-512" => Ok(DigestAlg::Sha2_512),
        b"SHA2-512/224" => Ok(DigestAlg::Sha2_512_224),
        b"SHA2-512/256" => Ok(DigestAlg::Sha2_512_256),
        b"SHA3-224" => Ok(DigestAlg::Sha3_224),
        b"SHA3-256" => Ok(DigestAlg::Sha3_256),
        b"SHA3-384" => Ok(DigestAlg::Sha3_384),
        b"SHA3-512" => Ok(DigestAlg::Sha3_512),
        #[cfg(feature = "rfc9580")]
        b"MD5" => Ok(DigestAlg::Md5),
        _ => Err(Error::new(ErrorKind::WrapperError)),
    }
}

/// Higher level wrapper for Digest operations
#[derive(Debug)]
pub struct OsslDigest {
    /// The OpenSSL message digest algorithm and context.
    alg: NativeDigestAlg,
    ctx: NativeDigestCtx,
    /// Digest size as reported by OpenSSL's `EVP_MD_get_size`.
    size: usize,
}

impl OsslDigest {
    /// Fully initializes a new digest context that is ready to ingest data
    pub fn new(
        ctx: &OsslContext,
        digest: DigestAlg,
        params: Option<&OsslParam>,
    ) -> Result<OsslDigest, Error> {
        let alg = NativeDigestAlg::fetch_in(
            ctx.as_lib_ctx(),
            digest_to_string(digest),
            None,
        )?;
        let size = alg.output_len();
        let dctx = if params.is_none() {
            alg.new_context()?
        } else {
            // For non-null params we call EVP_DigestInit_ex2 directly.
            let ptr = unsafe { EVP_MD_CTX_new() };
            if ptr.is_null() {
                trace_ossl!("EVP_MD_CTX_new()");
                return Err(Error::new(ErrorKind::NullPtr));
            }
            let ret = unsafe {
                EVP_DigestInit_ex2(
                    ptr,
                    alg.as_ptr() as *const EVP_MD,
                    params.map_or(std::ptr::null(), OsslParam::as_ptr),
                )
            };
            if ret != 1 {
                unsafe { EVP_MD_CTX_free(ptr) };
                trace_ossl!("EVP_DigestInit_ex2()");
                return Err(Error::new(ErrorKind::OsslError));
            }
            unsafe {
                NativeDigestCtx::from_ptr(ptr as *mut _)
            }
        };
        Ok(OsslDigest { alg, ctx: dctx, size })
    }

    /// Re-initializes an existing context discarding any existing state
    pub fn reset(&mut self, params: Option<&OsslParam>) -> Result<(), Error> {
        let ret = unsafe {
            EVP_DigestInit_ex2(
                self.ctx.as_ptr() as *mut EVP_MD_CTX,
                self.alg.as_ptr() as *const EVP_MD,
                match params {
                    Some(p) => p.as_ptr(),
                    None => std::ptr::null(),
                },
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_DigestInit_ex2()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Ingests data into the hashing mechanism
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        Ok(self.ctx.update(data)?)
    }

    /// Finalizes the state and produces the output digest
    /// No more operations are possible on this object unless `OsslDigest::reset` is
    /// called first.
    pub fn finalize(&mut self, digest: &mut [u8]) -> Result<usize, Error> {
        if digest.len() < self.size {
            return Err(Error::new(ErrorKind::BufferSize));
        }
        let mut retlen = c_uint::try_from(self.size)?;
        let ret = unsafe {
            EVP_DigestFinal_ex(
                self.ctx.as_ptr() as *mut EVP_MD_CTX,
                digest.as_mut_ptr(),
                &mut retlen,
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_DigestFinal_ex()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(retlen)?)
    }

    /// Provides the size of the expected output digest
    pub fn size(&self) -> usize {
        self.size
    }

    /// Tries to clone the digest.
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(OsslDigest {
            alg: self.alg.clone(),
            ctx: self.ctx.fork()?,
            size: self.size,
        })
    }

    #[cfg(ossl_v400)]
    pub fn get_state_size(&self) -> Result<usize, Error> {
        Ok(self.ctx.serialize_size()?)
    }
    #[cfg(not(ossl_v400))]
    pub fn get_state_size(&self) -> Result<usize, Error> {
        Err(Error::new(ErrorKind::WrapperError))
    }

    #[cfg(ossl_v400)]
    pub fn get_state(&self, state: &mut [u8]) -> Result<usize, Error> {
        Ok(self.ctx.serialize(state)?)
    }
    #[cfg(not(ossl_v400))]
    pub fn get_state(&self, _state: &mut [u8]) -> Result<usize, Error> {
        Err(Error::new(ErrorKind::WrapperError))
    }

    #[cfg(ossl_v400)]
    pub fn set_state(&mut self, state: &[u8]) -> Result<(), Error> {
        Ok(self.ctx.deserialize(state)?)
    }
    #[cfg(not(ossl_v400))]
    pub fn set_state(&mut self, _state: &[u8]) -> Result<(), Error> {
        Err(Error::new(ErrorKind::WrapperError))
    }
}

unsafe impl Send for OsslDigest {}
unsafe impl Sync for OsslDigest {}
