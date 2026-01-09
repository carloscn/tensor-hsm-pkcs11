# Secure HSM PKCS#11 Module - Main Makefile
# Unified build management for compilation, installation, and testing

.PHONY: all help clean distclean install uninstall test linux macos windows android ios

# Default target
.DEFAULT_GOAL := help

# Configuration variables
PLATFORM ?= linux
BUILD_DIR = build/$(PLATFORM)
INSTALL_DIR ?= /usr/lib/x86_64-linux-gnu/pkcs11
SRC_DIR = src

# Detect operating system
UNAME_S := $(shell uname -s 2>/dev/null || echo "Linux")
UNAME_M := $(shell uname -m 2>/dev/null || echo "x86_64")

# Help information
help:
	@echo "Secure HSM PKCS#11 Module - Build Management"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Main targets:"
	@echo "  make              - Show this help message"
	@echo "  make all          - Build module for current platform (default: Linux)"
	@echo "  make linux        - Build Linux version (x64)"
	@echo "  make macos        - Build macOS version (universal binary)"
	@echo "  make clean        - Clean build artifacts for current platform"
	@echo "  make distclean    - Clean build artifacts for all platforms"
	@echo "  make install      - Install module to system directory (requires sudo)"
	@echo "  make uninstall    - Remove module from system directory (requires sudo)"
	@echo "  make test         - Run test scripts"
	@echo ""
	@echo "Platform-specific targets:"
	@echo "  make windows      - Build Windows version"
	@echo "  make android      - Build Android version"
	@echo "  make ios          - Build iOS version"
	@echo ""
	@echo "Options:"
	@echo "  PLATFORM=<platform>   - Specify platform (linux/macos/windows/android/ios)"
	@echo "  INSTALL_DIR=<path>    - Specify installation directory (default: $(INSTALL_DIR))"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Show help"
	@echo "  make linux        # Build Linux version"
	@echo "  make clean        # Clean build files"
	@echo "  make install      # Install to system"
	@echo "  sudo make install INSTALL_DIR=/usr/local/lib/pkcs11"

# Default build (Linux)
all: linux

# Linux build
linux:
	@echo "Building Linux version..."
	@if [ ! -f "$(BUILD_DIR)/Makefile" ]; then \
		echo "Error: Cannot find $(BUILD_DIR)/Makefile"; \
		exit 1; \
	fi
	@cd $(BUILD_DIR) && $(MAKE) clean && $(MAKE)
	@echo "Build complete: $(BUILD_DIR)/libsecure_pkcs11_https.so"

# macOS build
macos:
	@echo "Building macOS version..."
	@if [ ! -f "build/macos/build.sh" ]; then \
		echo "Error: Cannot find build/macos/build.sh"; \
		exit 1; \
	fi
	@cd build/macos && bash build.sh
	@echo "Build complete: build/macos/empty-pkcs11.dylib"

# Windows build
windows:
	@echo "Building Windows version..."
	@if [ ! -f "build/windows/build.bat" ]; then \
		echo "Error: Cannot find build/windows/build.bat"; \
		echo "Note: Windows build must be run on Windows environment"; \
		exit 1; \
	fi
	@echo "Note: Please run build/windows/build.bat on Windows environment"

# Android build
android:
	@echo "Building Android version..."
	@if [ ! -f "build/android/build.bat" ]; then \
		echo "Error: Cannot find build/android/build.bat"; \
		echo "Note: Android build requires Android NDK"; \
		exit 1; \
	fi
	@echo "Note: Please run build/android/build.bat on Windows environment"

# iOS build
ios:
	@echo "Building iOS version..."
	@if [ ! -f "build/ios/build.sh" ]; then \
		echo "Error: Cannot find build/ios/build.sh"; \
		exit 1; \
	fi
	@cd build/ios && bash build.sh
	@echo "Build complete: build/ios/"

# Clean current platform
clean:
	@echo "Cleaning build files for $(PLATFORM) platform..."
	@if [ -f "$(BUILD_DIR)/Makefile" ]; then \
		cd $(BUILD_DIR) && $(MAKE) clean; \
	fi
	@echo "Clean complete"

# Clean all platforms
distclean:
	@echo "Cleaning build files for all platforms..."
	@for platform in linux macos windows android ios; do \
		if [ -f "build/$$platform/Makefile" ]; then \
			echo "Cleaning $$platform..."; \
			cd build/$$platform && $(MAKE) distclean 2>/dev/null || $(MAKE) clean 2>/dev/null || true; \
		fi; \
	done
	@echo "Clean complete"

# Install module
install: linux
	@echo "Installing module to $(INSTALL_DIR)..."
	@if [ ! -f "$(BUILD_DIR)/libsecure_pkcs11_https.so" ]; then \
		echo "Error: Cannot find build artifact $(BUILD_DIR)/libsecure_pkcs11_https.so"; \
		echo "Please run 'make linux' to build first"; \
		exit 1; \
	fi
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp $(BUILD_DIR)/libsecure_pkcs11_https.so $(INSTALL_DIR)/
	@sudo chmod 755 $(INSTALL_DIR)/libsecure_pkcs11_https.so
	@echo "Module installed: $(INSTALL_DIR)/libsecure_pkcs11_https.so"
	@echo ""
	@echo "Creating PKCS#11 module configuration..."
	@sudo mkdir -p /etc/pkcs11/modules
	@echo "module: $(INSTALL_DIR)/libsecure_pkcs11_https.so" | sudo tee /etc/pkcs11/modules/secure.module > /dev/null
	@sudo chmod 644 /etc/pkcs11/modules/secure.module
	@echo "PKCS#11 configuration created: /etc/pkcs11/modules/secure.module"
	@echo ""
	@echo "Installation complete!"
	@echo "  Module: $(INSTALL_DIR)/libsecure_pkcs11_https.so"
	@echo "  Config: /etc/pkcs11/modules/secure.module"

# Uninstall module
uninstall:
	@echo "Uninstalling module..."
	@if [ -f "$(INSTALL_DIR)/libsecure_pkcs11_https.so" ]; then \
		sudo rm -f $(INSTALL_DIR)/libsecure_pkcs11_https.so; \
		echo "Module removed: $(INSTALL_DIR)/libsecure_pkcs11_https.so"; \
	else \
		echo "Module not found at $(INSTALL_DIR)/libsecure_pkcs11_https.so"; \
	fi
	@if [ -f "/etc/pkcs11/modules/secure.module" ]; then \
		sudo rm -f /etc/pkcs11/modules/secure.module; \
		echo "PKCS#11 configuration removed: /etc/pkcs11/modules/secure.module"; \
	else \
		echo "PKCS#11 configuration not found at /etc/pkcs11/modules/secure.module"; \
	fi
	@echo "Uninstallation complete!"

# Run tests
test:
	@echo "Running tests..."
	@if [ ! -d "tests" ]; then \
		echo "Error: Cannot find tests directory"; \
		exit 1; \
	fi
	@if [ ! -f "$(BUILD_DIR)/libsecure_pkcs11_https.so" ]; then \
		echo "Warning: Cannot find build artifact, building first..."; \
		$(MAKE) linux; \
	fi
	@echo "Note: Please ensure the following environment variables are set:"
	@echo "  export PKCS11_SIGNING_URL=<your-signing-service-url>"
	@echo "  export PKCS11_CLIENT_CERT=/path/to/client.crt"
	@echo "  export PKCS11_CLIENT_KEY=/path/to/client.key"
	@echo "  export PKCS11_SIGNING_ENV=test"
	@echo ""
	@echo "Available test scripts:"
	@ls -1 tests/*.sh 2>/dev/null | sed 's|^|  |' || echo "  No test scripts found"

# Show build information
info:
	@echo "Build information:"
	@echo "  Operating System: $(UNAME_S)"
	@echo "  Architecture: $(UNAME_M)"
	@echo "  Platform: $(PLATFORM)"
	@echo "  Build Directory: $(BUILD_DIR)"
	@echo "  Source Directory: $(SRC_DIR)"
	@echo "  Install Directory: $(INSTALL_DIR)"
	@echo ""
	@if [ -f "$(BUILD_DIR)/libsecure_pkcs11_https.so" ]; then \
		echo "Build artifact: $(BUILD_DIR)/libsecure_pkcs11_https.so"; \
		ls -lh $(BUILD_DIR)/libsecure_pkcs11_https.so 2>/dev/null || true; \
	elif [ -f "build/macos/libsecure_pkcs11_https.dylib" ]; then \
		echo "Build artifact: build/macos/libsecure_pkcs11_https.dylib"; \
		ls -lh build/macos/libsecure_pkcs11_https.dylib 2>/dev/null || true; \
	else \
		echo "Build artifact: Not found"; \
	fi
