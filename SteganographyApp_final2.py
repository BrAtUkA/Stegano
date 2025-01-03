# | Stealth Messenger - Advanced Steganography App
# | Features: File/Text embedding, AES encryption, compression, auto bit-depth detection

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import tempfile
import uuid
import math
import zlib
import hashlib
import base64
import struct

# Optional encryption support
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

TEMP_DIR = tempfile.gettempdir()
SIGNATURE = b"ST3ALTH"  # New signature as bytes
SIGNATURE_LEN = len(SIGNATURE)

# Header structure after signature:
# [1 byte: version] [1 byte: bit_depth] [1 byte: flags] [1 byte: type] 
# Flags: bit 0 = compressed, bit 1 = encrypted
# Type: 0x00 = text, 0x01 = file
# If file: [2 bytes: filename_len] [filename_bytes] [4 bytes: data_len] [data]
# If text: [4 bytes: data_len] [data]
# Terminator: 4 null bytes

VERSION = 1
HEADER_SIZE = 4  # version + bit_depth + flags + type
TERMINATOR = b'\x00\x00\x00\x00'
TERMINATOR_LEN = 4

FLAG_COMPRESSED = 0x01
FLAG_ENCRYPTED = 0x02

TYPE_TEXT = 0x00
TYPE_FILE = 0x01


def derive_key(password: str, salt: bytes = None) -> tuple:
    """Derive a Fernet key from password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


class SteganographyApp(ctk.CTk):
    # Reference resolution (designed for 1080p)
    DESIGN_WIDTH = 1920
    DESIGN_HEIGHT = 1080
    
    # ------- INITIALIZATION -------
    def __init__(self):
        super().__init__()
        
        # Calculate and apply scaling based on screen resolution
        self._apply_resolution_scaling()
        
        self.title("Stealth Messenger")
        # Base dimensions - will be scaled automatically by CTk
        self._base_width = 800
        self._base_height = 950
        self._decode_height = 650
        self.geometry(f"{self._base_width}x{self._base_height}")
        self.resizable(True, True)

        self.original_title = "Stealth Messenger"
        self.encode_bit_depth = tk.IntVar(value=2)
        self.decode_bit_depth = tk.IntVar(value=2)
        self.use_compression = tk.BooleanVar(value=True)
        self.use_encryption = tk.BooleanVar(value=False)
        self.embed_mode = tk.StringVar(value="text")  # "text" or "file"
        
        self.original_image_path = None
        self.embedded_image_path = None
        self.decode_image_path = None
        self.full_decoded_message = ""
        self.file_to_embed_path = None
        self.file_to_embed_data = None
        self.extracted_file_data = None
        self.extracted_filename = None

        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(self.main_frame, text="Stealth Messenger", font=("Arial", 24, "bold")).pack(pady=(20, 15))

        self.tabview = ctk.CTkTabview(self.main_frame, width=780, corner_radius=10)
        self.tabview.pack(padx=10, pady=10)

        self.encode_tab = self.tabview.add("Encode")
        self.decode_tab = self.tabview.add("Decode")

        self.create_encode_tab()
        self.create_decode_tab()
        self.tabview.configure(command=self.on_tab_change)
    
    def _apply_resolution_scaling(self):
        """Calculate and apply scaling factor based on screen resolution."""
        # Get actual screen dimensions
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        # Calculate scale factors for width and height
        scale_w = screen_width / self.DESIGN_WIDTH
        scale_h = screen_height / self.DESIGN_HEIGHT
        
        # Use the smaller scale to ensure app fits on screen
        # Cap between 0.7 and 1.5 to avoid extremes
        scale_factor = min(scale_w, scale_h)
        scale_factor = max(0.7, min(1.5, scale_factor))
        
        # Apply scaling to all widgets globally
        ctk.set_widget_scaling(scale_factor)
        
        # Store for reference
        self.scale_factor = scale_factor

    # ------- UI CREATION FUNCTIONS -------
    def create_encode_tab(self):
        frames = self.create_frames(self.encode_tab, "Encode")

        # Left side - original image
        self.encode_image_label = self.create_image_section(
            frames["left_frame"], "Select Cover Image", self.browse_image)
        self.encode_image_preview = self.create_preview_label(frames["left_frame"])
        
        self.capacity_label = ctk.CTkLabel(
            frames["left_frame"], text="Capacity: N/A", font=("Arial", 12), text_color="gray60")
        self.capacity_label.pack(pady=(5, 10))

        # Right side - embedded image
        self.embedded_label = ctk.CTkLabel(frames["right_frame"], text="Embedded Image", font=("Arial", 16))
        self.embedded_label.pack(pady=(10, 10))
        self.embedded_preview = self.create_preview_label(frames["right_frame"])

        # Mode selector (Text or File) - centered
        mode_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        mode_frame.pack(pady=(10, 5))
        
        ctk.CTkLabel(mode_frame, text="Embed Mode:", font=("Arial", 14)).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(mode_frame, text="Text Message", variable=self.embed_mode, 
                          value="text", command=self.on_mode_change).pack(side="left", padx=10)
        ctk.CTkRadioButton(mode_frame, text="File", variable=self.embed_mode,
                          value="file", command=self.on_mode_change).pack(side="left", padx=10)

        # Text input frame
        self.text_input_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        self.text_input_frame.pack(pady=5, padx=20, fill="x")
        
        ctk.CTkLabel(self.text_input_frame, text="Enter Your Secret Message", font=("Arial", 14)).pack(pady=(5, 5))
        self.message_textbox = ctk.CTkTextbox(self.text_input_frame, height=100, width=740, font=("Arial", 13))
        self.message_textbox.pack(pady=5)
        self.message_textbox.bind("<KeyRelease>", self.update_message_info)

        self.message_info_label = ctk.CTkLabel(
            self.text_input_frame, text="0 bytes / Select image first",
            font=("Arial", 11), text_color="gray60")
        self.message_info_label.pack(pady=(0, 5))

        # File input frame (hidden by default) - centered, same height as text mode
        self.file_input_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        
        # Spacer to match text input height
        file_content_frame = ctk.CTkFrame(self.file_input_frame, fg_color="transparent", height=120)
        file_content_frame.pack(pady=10, fill="x")
        file_content_frame.pack_propagate(False)
        
        file_select_frame = ctk.CTkFrame(file_content_frame, fg_color="transparent")
        file_select_frame.pack(expand=True)
        
        ctk.CTkLabel(file_select_frame, text="Select File to Embed:", font=("Arial", 14)).pack(side="left", padx=(0, 10))
        ctk.CTkButton(file_select_frame, text="Browse File", command=self.browse_file_to_embed, width=120).pack(side="left")
        
        self.file_info_label = ctk.CTkLabel(self.file_input_frame, text="No file selected", 
                                            font=("Arial", 12), text_color="gray60")
        self.file_info_label.pack(pady=(0, 5))

        # Options frame - centered
        options_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        options_frame.pack(pady=10)

        # Compression checkbox
        self.compress_check = ctk.CTkCheckBox(options_frame, text="Compress data (recommended)", 
                                              variable=self.use_compression, command=self.update_message_info)
        self.compress_check.pack(side="left", padx=15)

        # Encryption checkbox
        encrypt_text = "Encrypt with password" if ENCRYPTION_AVAILABLE else "Encrypt (install cryptography)"
        self.encrypt_check = ctk.CTkCheckBox(options_frame, text=encrypt_text,
                                             variable=self.use_encryption, command=self.on_encryption_toggle)
        self.encrypt_check.pack(side="left", padx=15)
        if not ENCRYPTION_AVAILABLE:
            self.encrypt_check.configure(state="disabled")

        # Password frame (hidden by default) - centered
        self.password_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        ctk.CTkLabel(self.password_frame, text="Password:", font=("Arial", 12)).pack(side="left", padx=(0, 8))
        self.password_entry = ctk.CTkEntry(self.password_frame, width=180, show="•", placeholder_text="Enter password")
        self.password_entry.pack(side="left", padx=5)
        ctk.CTkLabel(self.password_frame, text="Confirm:", font=("Arial", 12)).pack(side="left", padx=(15, 8))
        self.password_confirm = ctk.CTkEntry(self.password_frame, width=180, show="•", placeholder_text="Confirm password")
        self.password_confirm.pack(side="left", padx=5)

        # Bit depth slider
        self.create_bit_slider(self.encode_tab, self.encode_bit_depth, self.update_bit_display)

        # Progress bar - centered
        self.encode_progress_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        self.encode_progress_frame.pack(pady=5)
        self.encode_progress = ctk.CTkProgressBar(self.encode_progress_frame, width=450)
        self.encode_progress.pack(side="left", padx=10)
        self.encode_progress.set(0)
        self.encode_progress_label = ctk.CTkLabel(self.encode_progress_frame, text="Ready", font=("Arial", 11), width=80)
        self.encode_progress_label.pack(side="left", padx=10)

        # Buttons
        button_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        button_frame.pack(pady=15)

        self.embed_button = self.create_button(
            button_frame, "Embed Data", self.embed_data, side="left")
        self.save_button = self.create_button(
            button_frame, "Save Image", self.save_image, side="right", state="disabled")

    def create_decode_tab(self):
        frames = self.create_frames(self.decode_tab, "Decode")

        # Left side - encoded image
        self.decode_image_label = self.create_image_section(
            frames["left_frame"], "Select Encoded Image", self.browse_decode_image)
        self.decode_image_preview = self.create_preview_label(frames["left_frame"])

        # Right side - decoded content
        ctk.CTkLabel(frames["right_frame"], text="Extracted Content", font=("Arial", 16)).pack(pady=(10, 10))
        self.decoded_message_textbox = ctk.CTkTextbox(
            frames["right_frame"], width=320, height=180, state="disabled",
            fg_color=("gray85", "gray15"), wrap="word")
        self.decoded_message_textbox.pack(pady=10)

        # Decode password frame
        decode_pw_frame = ctk.CTkFrame(self.decode_tab, fg_color="transparent")
        decode_pw_frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(decode_pw_frame, text="Password (if encrypted):", font=("Arial", 12)).pack(side="left", padx=(0, 10))
        self.decode_password_entry = ctk.CTkEntry(decode_pw_frame, width=250, show="•", placeholder_text="Leave empty if not encrypted")
        self.decode_password_entry.pack(side="left", padx=5)

        # Note about auto-detection
        self.decode_info_label = ctk.CTkLabel(self.decode_tab, 
            text="Bit depth, compression, and encryption are auto-detected from the embedded data.",
            font=("Arial", 11), text_color="gray60")
        self.decode_info_label.pack(pady=5)

        # Progress bar - centered
        self.decode_progress_frame = ctk.CTkFrame(self.decode_tab, fg_color="transparent")
        self.decode_progress_frame.pack(pady=5)
        self.decode_progress = ctk.CTkProgressBar(self.decode_progress_frame, width=450)
        self.decode_progress.pack(side="left", padx=10)
        self.decode_progress.set(0)
        self.decode_progress_label = ctk.CTkLabel(self.decode_progress_frame, text="Ready", font=("Arial", 11), width=80)
        self.decode_progress_label.pack(side="left", padx=10)

        button_frame = ctk.CTkFrame(self.decode_tab, fg_color="transparent")
        button_frame.pack(pady=15)

        self.extract_button = self.create_button(
            button_frame, "Extract Data", self.extract_data, width=150, height=45, side="left")
        self.save_extracted_button = self.create_button(
            button_frame, "Save Extracted", self.save_extracted_data,
            width=150, height=45, state="disabled", side="left")

    # Helper methods for UI creation
    def create_frames(self, parent, prefix):
        content_frame = ctk.CTkFrame(parent, fg_color="transparent")
        content_frame.pack(pady=10, padx=20, fill="x", expand=True)

        left_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        left_frame.pack(side="left", padx=10, fill="both", expand=True)

        right_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        right_frame.pack(side="right", padx=10, fill="both", expand=True)

        return {"content_frame": content_frame, "left_frame": left_frame, "right_frame": right_frame}

    def create_image_section(self, parent, text, command):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=10, fill="x")

        label = ctk.CTkLabel(frame, text=text, font=("Arial", 14))
        label.pack(side="left", padx=(0, 10))

        ctk.CTkButton(frame, text="Browse", command=command, width=90).pack(side="right")

        return label

    def create_preview_label(self, parent):
        preview = ctk.CTkLabel(
            parent, text="No image selected", width=300, height=180,
            corner_radius=10, fg_color=("gray85", "gray15"))
        preview.pack(pady=10)
        return preview

    def create_bit_slider(self, parent, variable, command):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=(5, 10), fill="x", padx=20)

        ctk.CTkLabel(frame, text="LSB Bits per channel:", font=("Arial", 13)).pack(side="left", padx=(0, 10))

        slider = ctk.CTkSlider(
            frame, from_=1, to=8, number_of_steps=7, variable=variable, command=command)
        slider.pack(side="left", expand=True, fill="x", padx=10)

        label = ctk.CTkLabel(frame, text="2 bits", width=50)
        label.pack(side="left", padx=5)

        if variable == self.encode_bit_depth:
            self.bit_value_label = label
        else:
            self.decode_bit_value_label = label

        return slider

    def create_button(self, parent, text, command, width=100, height=40, state="normal", side="left"):
        button = ctk.CTkButton(
            parent, text=text, command=command, width=width, height=height,
            font=("Arial", 15, "bold"), state=state)
        button.pack(side=side, padx=10)
        return button

    # ------- UI UPDATE FUNCTIONS -------
    def on_tab_change(self):
        if self.tabview.get() == "Encode":
            self.geometry(f"{self._base_width}x{self._base_height}")
        else:
            self.geometry(f"{self._base_width}x{self._decode_height}")

    def on_mode_change(self):
        if self.embed_mode.get() == "text":
            self.file_input_frame.pack_forget()
            self.text_input_frame.pack(pady=5, padx=20, fill="x", after=self.encode_tab.winfo_children()[1])
        else:
            self.text_input_frame.pack_forget()
            self.file_input_frame.pack(pady=5, padx=20, fill="x", after=self.encode_tab.winfo_children()[1])
        self.update_message_info()

    def on_encryption_toggle(self):
        if self.use_encryption.get():
            self.password_frame.pack(pady=5, after=self.encrypt_check.master)
        else:
            self.password_frame.pack_forget()

    def update_bit_display(self, value):
        bit_value = int(value)
        self.bit_value_label.configure(text=f"{bit_value} bit{'s' if bit_value > 1 else ''}")
        self.update_capacity_info()

    def update_progress(self, progress_bar, label, progress, text):
        progress_bar.set(progress / 100)
        label.configure(text=text)
        self.update_idletasks()

    def get_image_capacity(self, image_path, bit_depth):
        """Calculates the maximum number of payload bytes that can be stored."""
        if not image_path:
            return 0
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                with img.convert('RGB') as rgb_img:
                    width, height = rgb_img.size
            else:
                width, height = img.size

            total_bits = width * height * 3 * bit_depth
            total_bytes = total_bits // 8
            # Overhead: signature + header + terminator
            overhead = SIGNATURE_LEN + HEADER_SIZE + TERMINATOR_LEN + 20  # Extra buffer for salt etc
            payload_capacity = total_bytes - overhead
            return max(0, payload_capacity)
        except Exception:
            return 0

    def update_message_info(self, event=None):
        if self.embed_mode.get() == "text":
            message = self.message_textbox.get("1.0", tk.END).strip()
            data_bytes = message.encode('utf-8')
        else:
            if self.file_to_embed_data:
                data_bytes = self.file_to_embed_data
            else:
                self.message_info_label.configure(text="No file selected")
                return

        # Estimate compressed size
        original_size = len(data_bytes)
        if self.use_compression.get():
            try:
                compressed = zlib.compress(data_bytes, level=9)
                display_size = len(compressed)
                size_text = f"{self.format_size(original_size)} → {self.format_size(display_size)} (compressed)"
            except:
                display_size = original_size
                size_text = self.format_size(display_size)
        else:
            display_size = original_size
            size_text = self.format_size(display_size)

        if not self.original_image_path:
            if self.embed_mode.get() == "text":
                self.message_info_label.configure(text=f"{size_text} / Select image first")
            return

        bit_depth = self.encode_bit_depth.get()
        max_payload_bytes = self.get_image_capacity(self.original_image_path, bit_depth)
        capacity_text = self.format_size(max_payload_bytes)

        if self.embed_mode.get() == "text":
            self.message_info_label.configure(
                text=f"{size_text} / {capacity_text} capacity",
                text_color="red" if display_size > max_payload_bytes else "gray60")
        else:
            self.file_info_label.configure(
                text=f"{size_text} / {capacity_text} capacity",
                text_color="red" if display_size > max_payload_bytes else "gray60")

    def update_capacity_info(self):
        if not self.original_image_path:
            self.capacity_label.configure(text="Capacity: N/A")
            self.update_message_info()
            return

        try:
            bit_depth = self.encode_bit_depth.get()
            capacity_bytes = self.get_image_capacity(self.original_image_path, bit_depth)

            if capacity_bytes < 1024:
                capacity_str = f"{capacity_bytes} bytes"
            elif capacity_bytes < 1024 * 1024:
                capacity_str = f"{capacity_bytes/1024:.1f} KB"
            else:
                capacity_str = f"{capacity_bytes/(1024*1024):.2f} MB"

            self.capacity_label.configure(text=f"Capacity: {capacity_str}")
            self.update_message_info()

        except Exception:
            self.capacity_label.configure(text="Capacity: Error")

    # ------- FILE OPERATIONS -------
    def browse_image(self):
        self._browse_image("Select Cover Image", self.encode_image_label, self.encode_image_preview,
                          lambda path: setattr(self, 'original_image_path', path), self.update_capacity_info)

    def browse_decode_image(self):
        self._browse_image("Select Encoded Image", self.decode_image_label, self.decode_image_preview,
                          lambda path: setattr(self, 'decode_image_path', path))
        self.decoded_message_textbox.configure(state="normal")
        self.decoded_message_textbox.delete("1.0", tk.END)
        self.decoded_message_textbox.configure(state="disabled")
        self.save_extracted_button.configure(state="disabled")
        self.full_decoded_message = ""
        self.extracted_file_data = None
        self.extracted_filename = None

    def _browse_image(self, title, label, preview, set_path, callback=None):
        filename = filedialog.askopenfilename(
            title=title, filetypes=[("PNG files", "*.png"), ("All images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if filename:
            set_path(filename)
            basename = os.path.basename(filename)
            label.configure(text=self.truncate_filename(basename))
            self._display_image(filename, preview)
            if callback:
                callback()
            if 'original_image_path' in str(set_path):
                self.embedded_image_path = None
                self.embedded_preview.configure(image="", text="Embedded image will appear here")
                self.save_button.configure(state="disabled")
                self.embedded_label.configure(text="Embedded Image")

    def browse_file_to_embed(self):
        filename = filedialog.askopenfilename(
            title="Select File to Embed", filetypes=[("All files", "*.*")])
        if filename:
            try:
                with open(filename, 'rb') as f:
                    self.file_to_embed_data = f.read()
                self.file_to_embed_path = filename
                basename = os.path.basename(filename)
                size_kb = len(self.file_to_embed_data) / 1024
                if size_kb < 1024:
                    size_str = f"{size_kb:.1f} KB"
                else:
                    size_str = f"{size_kb/1024:.2f} MB"
                self.file_info_label.configure(text=f"📎 {basename} ({size_str})")
                self.update_message_info()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")

    def save_image(self):
        if not self.embedded_image_path or not os.path.exists(self.embedded_image_path):
            messagebox.showerror("Error", "No valid embedded image to save")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if save_path:
            try:
                from shutil import copy2
                copy2(self.embedded_image_path, save_path)
                messagebox.showinfo("Success", f"Image saved to {os.path.basename(save_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save: {e}")

    def save_extracted_data(self):
        if self.extracted_file_data is not None:
            # Save as file
            default_name = self.extracted_filename or "extracted_file"
            ext = os.path.splitext(default_name)[1] if self.extracted_filename else ""
            save_path = filedialog.asksaveasfilename(
                initialfile=default_name,
                defaultextension=ext,
                filetypes=[("All files", "*.*")])
            if save_path:
                try:
                    with open(save_path, 'wb') as f:
                        f.write(self.extracted_file_data)
                    messagebox.showinfo("Success", f"File saved to {os.path.basename(save_path)}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {e}")
        elif self.full_decoded_message:
            # Save as text
            save_path = filedialog.asksaveasfilename(
                defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if save_path:
                try:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(self.full_decoded_message)
                    messagebox.showinfo("Success", f"Message saved to {os.path.basename(save_path)}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save: {e}")
        else:
            messagebox.showerror("Error", "No data to save")

    # ------- HELPER FUNCTIONS -------
    def format_size(self, size_bytes):
        """Format bytes into human-readable KB/MB/GB."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def truncate_filename(self, filename, max_length=22):
        if len(filename) <= max_length:
            return filename
        name, ext = os.path.splitext(filename)
        prefix_len = max(0, max_length - len(ext) - 3 - 4)
        return name[:prefix_len] + "..." + name[-4:] + ext

    def _display_image(self, image_path, preview_label):
        try:
            img = Image.open(image_path)
            img.thumbnail((300, 180))
            photo = ImageTk.PhotoImage(img)
            preview_label.configure(image=photo, text="")
            preview_label.image = photo
        except Exception as e:
            preview_label.configure(image="", text=f"Error: {e}")
            preview_label.image = None

    # ------- STEGANOGRAPHY OPERATIONS -------
    def embed_data(self):
        if not self.original_image_path:
            messagebox.showerror("Error", "Please select a cover image first.")
            return

        # Get data to embed
        if self.embed_mode.get() == "text":
            message = self.message_textbox.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to embed.")
                return
            raw_data = message.encode('utf-8')
            data_type = TYPE_TEXT
            filename_bytes = b''
        else:
            if not self.file_to_embed_data:
                messagebox.showerror("Error", "Please select a file to embed.")
                return
            raw_data = self.file_to_embed_data
            data_type = TYPE_FILE
            filename_bytes = os.path.basename(self.file_to_embed_path).encode('utf-8')

        # Validate encryption password
        if self.use_encryption.get():
            if not ENCRYPTION_AVAILABLE:
                messagebox.showerror("Error", "cryptography library not installed.\nRun: pip install cryptography")
                return
            password = self.password_entry.get()
            confirm = self.password_confirm.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password for encryption.")
                return
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

        try:
            self.update_progress(self.encode_progress, self.encode_progress_label, 5, "Preparing data...")

            # Build flags
            flags = 0
            if self.use_compression.get():
                flags |= FLAG_COMPRESSED
            if self.use_encryption.get():
                flags |= FLAG_ENCRYPTED

            bit_depth = self.encode_bit_depth.get()

            # Process data: compress then encrypt
            processed_data = raw_data
            salt = b''

            if self.use_compression.get():
                self.update_progress(self.encode_progress, self.encode_progress_label, 10, "Compressing...")
                processed_data = zlib.compress(processed_data, level=9)

            if self.use_encryption.get():
                self.update_progress(self.encode_progress, self.encode_progress_label, 15, "Encrypting...")
                key, salt = derive_key(password)
                fernet = Fernet(key)
                processed_data = fernet.encrypt(processed_data)

            # Build payload structure
            # Header: version(1) + bit_depth(1) + flags(1) + type(1)
            header = bytes([VERSION, bit_depth, flags, data_type])

            if data_type == TYPE_FILE:
                # File: filename_len(2) + filename + data_len(4) + data
                payload = (
                    struct.pack('>H', len(filename_bytes)) +
                    filename_bytes +
                    struct.pack('>I', len(processed_data)) +
                    processed_data
                )
            else:
                # Text: data_len(4) + data
                payload = struct.pack('>I', len(processed_data)) + processed_data

            # If encrypted, prepend salt
            if self.use_encryption.get():
                payload = salt + payload

            # Full data: signature + header + payload + terminator
            data_to_embed = SIGNATURE + header + payload + TERMINATOR

            self.update_progress(self.encode_progress, self.encode_progress_label, 20, "Loading image...")

            # Load and prepare image
            original_img = Image.open(self.original_image_path)
            if original_img.mode != 'RGB':
                original_img = original_img.convert('RGB')

            embedded_img = original_img.copy()
            width, height = embedded_img.size

            # Check capacity
            max_bytes = (width * height * 3 * bit_depth) // 8
            if len(data_to_embed) > max_bytes:
                messagebox.showerror("Error", f"Data too large!\nData: {len(data_to_embed)} bytes\nCapacity: {max_bytes} bytes")
                self.update_progress(self.encode_progress, self.encode_progress_label, 0, "Ready")
                return

            # Convert to bits
            binary_data = ''.join(format(byte, '08b') for byte in data_to_embed)
            required_bits = len(binary_data)

            bit_mask = (1 << bit_depth) - 1
            clear_mask = ~bit_mask & 0xFF

            self.update_progress(self.encode_progress, self.encode_progress_label, 25, "Embedding...")

            # Embed data
            data_index = 0
            pixels = embedded_img.load()
            total_ops = math.ceil(required_bits / bit_depth)

            for y in range(height):
                for x in range(width):
                    if data_index >= required_bits:
                        break

                    pixel = list(pixels[x, y])

                    for i in range(3):
                        if data_index >= required_bits:
                            break

                        bits_str = binary_data[data_index:data_index + bit_depth].ljust(bit_depth, '0')
                        bits_int = int(bits_str, 2)

                        pixel[i] = (pixel[i] & clear_mask) | bits_int
                        data_index += bit_depth

                        # Update progress periodically
                        if data_index % 50000 == 0:
                            progress = 25 + (data_index / required_bits) * 70
                            self.update_progress(self.encode_progress, self.encode_progress_label, 
                                                progress, f"Embedding... {progress:.0f}%")

                    pixels[x, y] = tuple(pixel)

                if data_index >= required_bits:
                    break

            self.update_progress(self.encode_progress, self.encode_progress_label, 95, "Saving...")

            # Save to temp file
            temp_filename = f"stealth_{uuid.uuid4().hex[:8]}.png"
            temp_path = os.path.join(TEMP_DIR, temp_filename)
            embedded_img.save(temp_path, format="PNG")

            self.embedded_image_path = temp_path
            self._display_image(temp_path, self.embedded_preview)
            self.save_button.configure(state="normal")
            self.embedded_label.configure(text="✓ Successfully Embedded")

            self.update_progress(self.encode_progress, self.encode_progress_label, 100, "Complete!")

            mode_str = "File" if data_type == TYPE_FILE else "Message"
            extras = []
            if self.use_compression.get():
                extras.append("compressed")
            if self.use_encryption.get():
                extras.append("encrypted")
            extras_str = f" ({', '.join(extras)})" if extras else ""
            
            messagebox.showinfo("Success", f"{mode_str} embedded successfully!{extras_str}")

        except Exception as e:
            self.update_progress(self.encode_progress, self.encode_progress_label, 0, "Error")
            messagebox.showerror("Error", f"Failed to embed: {e}")
            if hasattr(self, 'embedded_image_path') and self.embedded_image_path and os.path.exists(self.embedded_image_path):
                try:
                    os.remove(self.embedded_image_path)
                except:
                    pass
            self.embedded_image_path = None
            self.save_button.configure(state="disabled")

    def extract_data(self):
        if not self.decode_image_path:
            messagebox.showerror("Error", "Please select an encoded image first")
            return

        try:
            self.update_progress(self.decode_progress, self.decode_progress_label, 5, "Loading image...")

            img = Image.open(self.decode_image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            width, height = img.size
            pixels = img.load()

            # First, extract with bit depth 1-8 to find signature
            # We'll try common bit depths first
            found_bit_depth = None
            
            for try_depth in [2, 1, 3, 4, 5, 6, 7, 8]:
                test_bytes = self._extract_bytes(pixels, width, height, try_depth, SIGNATURE_LEN + 10)
                if test_bytes[:SIGNATURE_LEN] == SIGNATURE:
                    found_bit_depth = try_depth
                    break

            if found_bit_depth is None:
                messagebox.showerror("Error", "No valid ST3ALTH signature found.\nThis image may not contain embedded data.")
                self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                return

            self.update_progress(self.decode_progress, self.decode_progress_label, 15, "Reading header...")

            # Read header
            header_data = self._extract_bytes(pixels, width, height, found_bit_depth, 
                                             SIGNATURE_LEN + HEADER_SIZE + 100)
            
            version = header_data[SIGNATURE_LEN]
            stored_bit_depth = header_data[SIGNATURE_LEN + 1]
            flags = header_data[SIGNATURE_LEN + 2]
            data_type = header_data[SIGNATURE_LEN + 3]

            is_compressed = bool(flags & FLAG_COMPRESSED)
            is_encrypted = bool(flags & FLAG_ENCRYPTED)

            # Use stored bit depth for full extraction
            bit_depth = stored_bit_depth

            self.update_progress(self.decode_progress, self.decode_progress_label, 20, "Extracting data...")

            # Extract all data until terminator
            extracted_bytes = self._extract_until_terminator(pixels, width, height, bit_depth, 
                                                             self.decode_progress, self.decode_progress_label)

            if extracted_bytes is None:
                messagebox.showerror("Error", "Failed to find data terminator. Data may be corrupted.")
                self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                return

            # Parse extracted data
            pos = SIGNATURE_LEN + HEADER_SIZE

            # Handle salt if encrypted
            salt = b''
            if is_encrypted:
                salt = extracted_bytes[pos:pos + 16]
                pos += 16

            if data_type == TYPE_FILE:
                filename_len = struct.unpack('>H', extracted_bytes[pos:pos + 2])[0]
                pos += 2
                filename = extracted_bytes[pos:pos + filename_len].decode('utf-8')
                pos += filename_len
                data_len = struct.unpack('>I', extracted_bytes[pos:pos + 4])[0]
                pos += 4
                payload = extracted_bytes[pos:pos + data_len]
            else:
                filename = None
                data_len = struct.unpack('>I', extracted_bytes[pos:pos + 4])[0]
                pos += 4
                payload = extracted_bytes[pos:pos + data_len]

            self.update_progress(self.decode_progress, self.decode_progress_label, 85, "Processing...")

            # Decrypt if needed
            if is_encrypted:
                if not ENCRYPTION_AVAILABLE:
                    messagebox.showerror("Error", "Data is encrypted but cryptography library not installed.")
                    self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                    return
                
                password = self.decode_password_entry.get()
                if not password:
                    messagebox.showerror("Error", "This data is encrypted. Please enter the password.")
                    self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                    return
                
                try:
                    key, _ = derive_key(password, salt)
                    fernet = Fernet(key)
                    payload = fernet.decrypt(payload)
                except Exception:
                    messagebox.showerror("Error", "Decryption failed. Wrong password?")
                    self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                    return

            # Decompress if needed
            if is_compressed:
                try:
                    payload = zlib.decompress(payload)
                except Exception as e:
                    messagebox.showerror("Error", f"Decompression failed: {e}")
                    self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Ready")
                    return

            self.update_progress(self.decode_progress, self.decode_progress_label, 95, "Finalizing...")

            # Display result
            self.decoded_message_textbox.configure(state="normal")
            self.decoded_message_textbox.delete("1.0", tk.END)

            if data_type == TYPE_FILE:
                self.extracted_file_data = payload
                self.extracted_filename = filename
                self.full_decoded_message = ""
                
                size_kb = len(payload) / 1024
                size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"
                
                info_text = f"📁 Extracted File:\n\nFilename: {filename}\nSize: {size_str}\n\n"
                info_text += "Click 'Save Extracted' to save the file."
                self.decoded_message_textbox.insert("1.0", info_text)
            else:
                self.extracted_file_data = None
                self.extracted_filename = None
                try:
                    message = payload.decode('utf-8')
                except:
                    message = payload.decode('utf-8', errors='replace')
                
                self.full_decoded_message = message
                
                # Truncate for display if very long
                if len(message) > 50000:
                    display_text = message[:50000] + f"\n\n[...{len(message) - 50000:,} more characters...]"
                else:
                    display_text = message
                self.decoded_message_textbox.insert("1.0", display_text)

            self.decoded_message_textbox.configure(state="disabled")
            self.save_extracted_button.configure(state="normal")

            self.update_progress(self.decode_progress, self.decode_progress_label, 100, "Complete!")

            extras = []
            if is_compressed:
                extras.append("compressed")
            if is_encrypted:
                extras.append("encrypted")
            extras_str = f" (was {', '.join(extras)})" if extras else ""
            type_str = "File" if data_type == TYPE_FILE else "Message"
            
            messagebox.showinfo("Success", f"{type_str} extracted successfully!{extras_str}")

        except Exception as e:
            self.update_progress(self.decode_progress, self.decode_progress_label, 0, "Error")
            messagebox.showerror("Error", f"Extraction failed: {e}")

    def _extract_bytes(self, pixels, width, height, bit_depth, num_bytes):
        """Extract a specific number of bytes from image."""
        bit_mask = (1 << bit_depth) - 1
        bits_needed = num_bytes * 8
        extracted_bits = ""
        
        for y in range(height):
            for x in range(width):
                if len(extracted_bits) >= bits_needed:
                    break
                pixel = pixels[x, y]
                for c in range(3):
                    if len(extracted_bits) >= bits_needed:
                        break
                    extracted_bits += format(pixel[c] & bit_mask, f'0{bit_depth}b')
            if len(extracted_bits) >= bits_needed:
                break
        
        # Convert bits to bytes
        result = bytearray()
        for i in range(0, min(len(extracted_bits), bits_needed), 8):
            byte_str = extracted_bits[i:i + 8]
            if len(byte_str) == 8:
                result.append(int(byte_str, 2))
        
        return bytes(result)

    def _extract_until_terminator(self, pixels, width, height, bit_depth, progress_bar, progress_label):
        """Extract bytes until terminator is found."""
        bit_mask = (1 << bit_depth) - 1
        extracted_bytes = bytearray()
        extracted_bits = ""
        total_pixels = width * height
        pixels_done = 0
        
        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                pixels_done += 1
                
                if pixels_done % 10000 == 0:
                    progress = 20 + (pixels_done / total_pixels) * 60
                    self.update_progress(progress_bar, progress_label, progress, f"Extracting... {progress:.0f}%")
                
                for c in range(3):
                    extracted_bits += format(pixel[c] & bit_mask, f'0{bit_depth}b')
                    
                    while len(extracted_bits) >= 8:
                        byte_val = int(extracted_bits[:8], 2)
                        extracted_bits = extracted_bits[8:]
                        extracted_bytes.append(byte_val)
                        
                        # Check for terminator
                        if len(extracted_bytes) >= TERMINATOR_LEN:
                            if extracted_bytes[-TERMINATOR_LEN:] == bytearray(TERMINATOR):
                                return bytes(extracted_bytes[:-TERMINATOR_LEN])
        
        return None


if __name__ == "__main__":
    # Clean up old temp files
    try:
        for item in os.listdir(TEMP_DIR):
            if item.startswith("stealth_") and item.endswith(".png"):
                os.remove(os.path.join(TEMP_DIR, item))
    except:
        pass

    app = SteganographyApp()
    app.mainloop()

    # Clean up on exit
    try:
        for item in os.listdir(TEMP_DIR):
            if item.startswith("stealth_") and item.endswith(".png"):
                os.remove(os.path.join(TEMP_DIR, item))
    except:
        pass
