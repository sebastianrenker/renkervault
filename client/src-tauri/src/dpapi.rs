#[cfg(target_os = "windows")]
mod win {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let v = slice.to_vec();
        LocalFree(out.pbData as *mut core::ffi::c_void);
        v
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(data);
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!("CryptProtectData fehlgeschlagen: {}", std::io::Error::last_os_error()));
        }
        Ok(unsafe { take(output) })
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(data);
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!("CryptUnprotectData fehlgeschlagen: {}", std::io::Error::last_os_error()));
        }
        Ok(unsafe { take(output) })
    }
}

#[cfg(target_os = "windows")]
pub use win::{protect, unprotect};

#[cfg(not(target_os = "windows"))]
pub fn protect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI ist nur unter Windows verfügbar".into())
}

#[cfg(not(target_os = "windows"))]
pub fn unprotect(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI ist nur unter Windows verfügbar".into())
}

#[tauri::command]
pub fn dpapi_available() -> bool {
    cfg!(target_os = "windows")
}

#[tauri::command]
pub fn dpapi_protect(data: Vec<u8>) -> Result<Vec<u8>, String> {
    protect(&data)
}

#[tauri::command]
pub fn dpapi_unprotect(data: Vec<u8>) -> Result<Vec<u8>, String> {
    unprotect(&data)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_original_bytes() {
        let secret = b"renkervault-master-key-test-value-32b!!".to_vec();
        let protected = protect(&secret).expect("protect");
        assert_ne!(protected, secret);
        let recovered = unprotect(&protected).expect("unprotect");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn protected_blob_does_not_trivially_contain_plaintext() {
        let secret = b"another-distinct-test-secret-value".to_vec();
        let protected = protect(&secret).expect("protect");
        let found = protected
            .windows(secret.len())
            .any(|w| w == secret.as_slice());
        assert!(!found, "Klartext duerfte nicht unveraendert im geschuetzten Blob vorkommen");
    }

    #[test]
    fn corrupted_blob_fails_to_unprotect() {
        let secret = b"yet-another-test-secret-for-corruption".to_vec();
        let mut protected = protect(&secret).expect("protect");
        let last = protected.len() - 1;
        protected[last] ^= 0xFF;
        assert!(unprotect(&protected).is_err());
    }

    #[test]
    fn empty_input_roundtrips() {
        let secret: Vec<u8> = vec![];
        let protected = protect(&secret).expect("protect");
        let recovered = unprotect(&protected).expect("unprotect");
        assert_eq!(recovered, secret);
    }
}
