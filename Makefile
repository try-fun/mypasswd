run:
	cargo run

build:
	cargo build  --release

install:build
	cp target/release/mypasswd  /usr/local/bin/