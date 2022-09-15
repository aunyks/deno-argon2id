use argon2::Argon2;

/// Dereference a pointer to the item it points
/// to in memory.
///
/// Security assumptions:
/// - `ptr` absolutely *cannot* be null, otherwise the program will panic
fn from_mut_ptr<T>(ptr: *mut T) -> &'static mut T {
    unsafe { &mut *ptr }
}

#[no_mangle]
pub extern "C" fn alloc_bytes(num_bytes: i32) -> *mut u8 {
    let capacity = num_bytes as usize;
    let mut vec = vec![0; capacity];
    let vec_ptr = vec.as_mut_ptr();
    std::mem::forget(vec);
    vec_ptr
}

#[no_mangle]
pub extern "C" fn free_bytes(vec_ptr: *mut u8, num_bytes: i32) {
    let num_bytes = num_bytes as usize;
    let vec = unsafe { Vec::from_raw_parts(vec_ptr, num_bytes, num_bytes) };
    std::mem::drop(vec);
}

#[no_mangle]
pub extern "C" fn alloc_default_argon2() -> *mut Argon2<'static> {
    Box::into_raw(Box::new(Argon2::default()))
}

#[no_mangle]
pub extern "C" fn free_argon2(argon2_ptr: *mut Argon2<'static>) {
    unsafe { Box::from_raw(argon2_ptr) };
}

#[no_mangle]
pub extern "C" fn hash_password(
    argon2_ptr: *mut Argon2<'static>,
    password_ptr: *mut u8,
    password_len: i32,
    salt_ptr: *mut u8,
    salt_len: i32,
    output_len: i32,
) -> *mut u8 {
    let argon2 = from_mut_ptr(argon2_ptr);
    let password_len = password_len as usize;
    let password = unsafe { Vec::from_raw_parts(password_ptr, password_len, password_len) };
    let salt_len = salt_len as usize;
    let salt = unsafe { Vec::from_raw_parts(salt_ptr, salt_len, salt_len) };

    let mut output_bytes = vec![0; output_len as usize];
    argon2
        .hash_password_into(&password, &salt, &mut output_bytes)
        .unwrap();

    let output_bytes_ptr = output_bytes.as_mut_ptr();
    std::mem::forget(output_bytes);
    output_bytes_ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_hash() {
        let mut i = 0;
        while i < 5 {
            let argon2 = alloc_default_argon2();
            // Don't need to free the two allocations below here because
            // they get dropped in hash_password() when they're reconstructed
            // from raw parts
            let pw_len = 32;
            let pw = alloc_bytes(pw_len);
            let salt_len = 16;
            let salt = alloc_bytes(salt_len);
            let output_len = 32;
            let h = hash_password(argon2, pw, pw_len, salt, salt_len, output_len);

            let v = unsafe { Vec::from_raw_parts(h, output_len as usize, output_len as usize) };
            assert_eq!(
                v,
                vec![
                    181, 152, 37, 200, 19, 128, 114, 20, 142, 97, 143, 93, 173, 121, 157, 18, 129,
                    206, 78, 181, 94, 163, 144, 60, 166, 221, 117, 153, 206, 176, 185, 224
                ]
            );

            free_argon2(argon2);
            i += 1;
        }
    }
}
