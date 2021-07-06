FROM fedora:latest

RUN dnf install -y \
	tpm2-tss-devel tpm2-abrmd tpm2-tools \
	swtpm swtpm-tools \
	rust clippy cargo \
	llvm llvm-devel clang pkg-config \
	dbus-daemon czmq-devel \
	python3

RUN cargo install cargo-tarpaulin

