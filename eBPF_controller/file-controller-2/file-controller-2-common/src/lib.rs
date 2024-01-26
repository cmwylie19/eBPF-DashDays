#![no_std]


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileLog {
    pub file_name: [u8; 256],      
    pub file_location: [u8; 256], 
    pub uid: u64,
    pub action: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileLog {}
