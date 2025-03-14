use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::Command;
use std::str;

enum Type {
    I32,
    I64,
}

impl Type {
    fn to_string(&self) -> String {
        match self {
            Type::I32 => "32".to_string(),
            Type::I64 => "64".to_string(),
        }
    }
}

fn get_syscall_return() -> String {
    todo!()
}

fn get_syscall_params() -> String {
    todo!()
}

fn gen_lookup_table(t: Type) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("uname").arg("-m").output()?;
    let cpu_arch = str::from_utf8(&output.stdout)?.trim();

    let header_dir = format!("/usr/include/{}-linux-gnu/asm", cpu_arch);
    let header_file_path = format!("{}/unistd_{}.h", header_dir, t.to_string());
    if !Path::new(&header_file_path).exists() {
        Err(format!("[{}] does not exist", header_file_path))?;
    }
    let output_file =
        File::create(format!("../includes/lookup_table_{}.h", t.to_string()).as_str())?;
    let mut writer = BufWriter::new(output_file);
    writeln!(
        writer,
        "{}",
        format!("#ifndef LOOKUP_TABLE_{}_H", t.to_string()).as_str()
    )?;
    writeln!(
        writer,
        "{}",
        format!("#define LOOKUP_TABLE_{}_H\n", t.to_string()).as_str()
    )?;
    writeln!(
        writer,
        "{}",
        format!("#define LOOKUP_TABLE_{} {{ \\", t.to_string()).as_str()
    )?;
    let file_handler = File::open(header_file_path)?;
    let reader = BufReader::new(file_handler);
    for line in reader.lines() {
        let line = line?;
        if line.starts_with("#define __NR_") {
            let syscall = line.split_whitespace().collect::<Vec<&str>>()[1]
                .split("__NR_")
                .collect::<Vec<&str>>()[1];
            let syscall_number = line.split_whitespace().collect::<Vec<&str>>()[2];
            writeln!(
                writer,
                "{}",
                format!("\t[{}] = {{\"{}\", {}, {} }},\\", syscall_number, syscall).as_str(),
                get_syscall_params(),
                get_syscall_return()
            )?;
        }
    }
    writeln!(writer, "{}", "}\n")?;
    writeln!(writer, "{}", "#endif")?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    gen_lookup_table(Type::I32)?;
    gen_lookup_table(Type::I64)?;
    Ok(())
}
