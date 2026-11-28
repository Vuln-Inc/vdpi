# Flatpak Packaging (`io.github.vuln_inc.vdpi`)

Build and install **vdpi Desktop** locally as a Flatpak on Linux:

```bash
# Install runtime, SDK, and Rust/Node extensions once
flatpak install -y flathub \
  org.gnome.Platform//49 \
  org.gnome.Sdk//49 \
  org.freedesktop.Sdk.Extension.rust-stable//25.08 \
  org.freedesktop.Sdk.Extension.node22//25.08

# Clone Flathub shared-modules for libayatana-appindicator tray support
git clone --depth 1 https://github.com/flathub/shared-modules.git packaging/flatpak/shared-modules

# Build and install locally
flatpak-builder --user --install --force-clean build-dir packaging/flatpak/io.github.vuln_inc.vdpi.yml
flatpak run io.github.vuln_inc.vdpi
```
