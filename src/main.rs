extern crate rpassword;
mod ciphertext;
use rpassword::read_password;
use std::io::Write;

fn check_env() {
    // need vim
}

fn main() {
    check_env();

    // 密码验证
    print!("Type a password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    if password != ciphertext::THIS_KEY {
        print!("password wrong\n");
        return;
    }

    // 解密
    ciphertext::decrypt_text();
    // 调用vim编辑
    std::process::Command::new("/usr/bin/vim")
        .arg(ciphertext::get_mypasswd().unwrap())
        .spawn()
        .expect("open vim failed")
        .wait()
        .expect("vim returned a non-zero status");

    // 加密
    ciphertext::encrypt_text()
}
