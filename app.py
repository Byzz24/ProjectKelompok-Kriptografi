import streamlit as st
import sqlite3
import os
import io
import base64
from PIL import Image
import numpy as np
import hashlib

from Crypto.Cipher import AES, Blowfish, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

st.set_page_config(page_title="PolyCipher", layout="centered", page_icon="🗝️")
ph = PasswordHasher()

def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """)
    
    with sqlite3.connect('data.db') as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data_label TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """)
    
    if "encrypted_output_bytes" not in st.session_state:
        st.session_state.encrypted_output_bytes = None


def register_user(username, password):
    if not username or not password:
        return False, "Username dan password tidak boleh kosong."
    
    try:
        password_hash = ph.hash(password)
        
        with sqlite3.connect('users.db') as conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                         (username, password_hash))
            conn.commit()
            return True, "Registrasi berhasil! Silakan login."
    except sqlite3.IntegrityError:
        return False, "Username sudah digunakan."
    except Exception as e:
        return False, f"Error saat hashing: {e}"

def verify_user(username, password):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        
        if user_row:
            user_id, stored_hash = user_row
            try:
                ph.verify(stored_hash, password)
                return True, user_id
            except VerifyMismatchError:
                return False, "Password salah."
            except Exception as e:
                return False, f"Error verifikasi: {e}"
        else:
            return False, "Username tidak ditemukan."

def get_encryption_keys(password, salt, dkLen):
    password_bytes = password.encode('utf-8')
    return PBKDF2(password_bytes, salt, dkLen=dkLen, count=100000, hmac_hash_module=SHA512)

def get_database_key(password):
    VAULT_KDF_SALT = b'poly-cipher-vault-salt-v1'
    password_bytes = password.encode('utf-8')
    return PBKDF2(password_bytes, VAULT_KDF_SALT, dkLen=32, count=100000, hmac_hash_module=SHA512)


def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            offset = ord('a')
            new_ord = (ord(char) - offset + (shift if mode == 'encrypt' else -shift)) % 26
            result += chr(new_ord + offset)
        elif 'A' <= char <= 'Z':
            offset = ord('A')
            new_ord = (ord(char) - offset + (shift if mode == 'encrypt' else -shift)) % 26
            result += chr(new_ord + offset)
        else:
            result += char
    return result

def vigenere_cipher(text, key, mode='encrypt'):
    key = key.upper().replace(" ", "")
    if not key: key = "POLYCIPHER"
    
    result = ""
    key_index = 0
    for char in text:
        if 'a' <= char <= 'z':
            offset = ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            if mode != 'encrypt': key_shift = -key_shift
            
            new_ord = (ord(char) - offset + key_shift) % 26
            result += chr(new_ord + offset)
            key_index += 1
        elif 'A' <= char <= 'Z':
            offset = ord('A')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            if mode != 'encrypt': key_shift = -key_shift
                
            new_ord = (ord(char) - offset + key_shift) % 26
            result += chr(new_ord + offset)
            key_index += 1
        else:
            result += char
    return result

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_lsb(image_file, secret_message):
    img = Image.open(image_file).convert('RGB')
    data = np.array(img)
    
    secret_message += "::END::"
    binary_secret = text_to_binary(secret_message)
    
    data_flat = data.flatten()
    
    if len(binary_secret) > len(data_flat):
        raise ValueError("Pesan terlalu panjang untuk gambar ini.")

    for i in range(len(binary_secret)):
        data_flat[i] = (data_flat[i] & 254) | int(binary_secret[i])
        
    new_data = data_flat.reshape(data.shape)
    new_img = Image.fromarray(new_data.astype('uint8'), 'RGB')
    
    img_buffer = io.BytesIO()
    new_img.save(img_buffer, format='PNG') 
    return img_buffer.getvalue()

def reveal_lsb(image_file):
    img = Image.open(image_file).convert('RGB')
    data = np.array(img)
    data_flat = data.flatten()
    
    binary_data = ""
    byte_data = ""
    message = ""
    
    delimiter = "::END::"
    delimiter_len = len(delimiter)
    
    for pixel_val in data_flat:
        binary_data += str(pixel_val & 1)
        
        if len(binary_data) == 8:
            try:
                char = chr(int(binary_data, 2))
                byte_data += char
                binary_data = ""
                
                if byte_data.endswith(delimiter):
                    message = byte_data[:-delimiter_len]
                    break
            except Exception:
                binary_data = ""
                continue
                
    return message

def show_login_page():
    st.title("🗝️ PolyCipher")
    st.subheader("Pusat Kriptografi Terpadu Anda")
    
    if 'page' not in st.session_state:
        st.session_state.page = 'Login'

    if st.session_state.page == 'Login':
        with st.form("login_form"):
            st.header("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Login")

            if login_button:
                verified, user_id_or_msg = verify_user(username, password)
                if verified:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.user_id = user_id_or_msg
                    st.rerun()
                else:
                    st.error(user_id_or_msg)
        
        if st.button("Belum punya akun? Registrasi"):
            st.session_state.page = 'Register'
            st.rerun()

    elif st.session_state.page == 'Register':
        with st.form("register_form"):
            st.header("Registrasi")
            reg_username = st.text_input("Username Baru")
            reg_password = st.text_input("Password Baru", type="password")
            reg_confirm_password = st.text_input("Konfirmasi Password", type="password")
            register_button = st.form_submit_button("Registrasi")

            if register_button:
                if reg_password != reg_confirm_password:
                    st.error("Password tidak cocok.")
                else:
                    success, message = register_user(reg_username, reg_password)
                    if success:
                        st.success(message)
                        st.session_state.page = 'Login'
                        st.rerun()
                    else:
                        st.error(message)
        
        if st.button("Sudah punya akun? Login"):
            st.session_state.page = 'Login'
            st.rerun()

def reset_encrypted_output():
    st.session_state.encrypted_output_bytes = None

def show_main_app():
    st.sidebar.title(f"Selamat Datang, {st.session_state.username}")
    if st.sidebar.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    st.title("🗝️ PolyCipher")
    st.text("Pilih utilitas kriptografi dari tumpukan (stack) algoritma kami.")
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "📜 **Super Enkripsi Teks**", 
        "🖼️ **Steganografi Gambar**", 
        "🗃️ **Enkripsi File**",
        "🔐 **Brankas Data**"
    ])

    with tab1:
        st.header("Rantai Enkripsi 'PolyCipher'")
        st.caption("Bangun rantai enkripsi Anda sendiri. Urutan pemilihan penting.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Enkripsi")
            
            enc_text = st.text_area("Pesan Teks", height=150, key="enc_text", on_change=reset_encrypted_output)
            enc_pass = st.text_input("Password Enkripsi", type="password", key="enc_pass", on_change=reset_encrypted_output)
            enc_v_key = st.text_input("Kunci Vigenère", key="enc_v_key", help="Kunci untuk lapisan Vigenère.", on_change=reset_encrypted_output)
            enc_c_shift = st.number_input("Pergeseran Caesar", min_value=1, max_value=25, value=3, key="enc_c_shift", on_change=reset_encrypted_output)

            st.markdown("---")
            st.write("**Stage 1: Lapisan Klasik (Teks)**")
            classic_choices = st.multiselect("Pilih 0-2 (dijalankan berurutan):", ["Caesar", "Vigenère"], key="c_choice_enc", on_change=reset_encrypted_output)
            
            st.write("**Stage 2: Lapisan Modern (Bytes)**")
            modern_choices = st.multiselect("Pilih 0 atau 1:", ["AES-128-EAX"], key="m_choice_enc", on_change=reset_encrypted_output)
            st.markdown("---")

            if st.button("Enkripsi Teks"):
                if not enc_text or not enc_pass:
                    st.warning("Harap isi pesan teks dan password.")
                elif not classic_choices and not modern_choices:
                    st.error("Pilih minimal 1 algoritma enkripsi.")
                else:
                    try:
                        if not modern_choices:
                            st.warning("🚨 PERINGATAN: Anda tidak memilih lapisan modern. Enkripsi klasik TIDAK AMAN dan mudah dipecahkan. Gunakan hanya untuk edukasi.")
                        
                        processed_text = enc_text
                        for choice in classic_choices:
                            if choice == "Caesar":
                                processed_text = caesar_cipher(processed_text, enc_c_shift, 'encrypt')
                            elif choice == "Vigenère":
                                if not enc_v_key:
                                    st.error("Kunci Vigenère tidak boleh kosong.")
                                    raise ValueError("Kunci Vigenère kosong")
                                processed_text = vigenere_cipher(processed_text, enc_v_key, 'encrypt')
                        
                        processed_bytes = processed_text.encode('utf-8')
                        
                        salt = get_random_bytes(16)
                        keys = get_encryption_keys(enc_pass, salt, 16)
                        key_aes128 = keys[0:16]
                        
                        final_data = processed_bytes
                        
                        for choice in modern_choices:
                            if choice == "AES-128-EAX":
                                cipher_aes128 = AES.new(key_aes128, AES.MODE_EAX, mac_len=16) 
                                nonce_aes128 = cipher_aes128.nonce
                                ct_aes128, tag_aes128 = cipher_aes128.encrypt_and_digest(final_data)
                                final_data = nonce_aes128 + tag_aes128 + ct_aes128
                        
                        output_bytes = salt + final_data
                        
                        st.session_state.encrypted_output_bytes = output_bytes
                        st.success("Enkripsi Berhasil!")
                        
                    except Exception as e:
                        st.error(f"Error Enkripsi: {e}")

            if st.session_state.get("encrypted_output_bytes") is not None:
                
                output_b64 = base64.b64encode(st.session_state.encrypted_output_bytes).decode('utf-8')
                st.text_area("Hasil (Base64)", value=output_b64, height=150, key="output_text_area", disabled=True)

                st.markdown("---")
                st.subheader("Simpan ke Brankas Data")
                st.caption("Data di atas akan dienkripsi lagi dengan **AES-256-GCM** sebelum disimpan ke database.")
                
                with st.form("save_to_vault_form"):
                    db_pass = st.text_input("Masukkan Password Brankas", type="password", key="db_pass_save")
                    db_label = st.text_input("Label Data", key="db_label_save")
                    save_button = st.form_submit_button("Simpan ke Brankas")
                    
                    if save_button:
                        if db_pass and db_label:
                            try:
                                bytes_to_save = st.session_state.encrypted_output_bytes
                                
                                key_aes_gcm_db = get_database_key(db_pass)
                                
                                cipher_aes_db = AES.new(key_aes_gcm_db, AES.MODE_GCM)
                                nonce_aes_db = cipher_aes_db.nonce
                                ct_aes_db, tag_aes_db = cipher_aes_db.encrypt_and_digest(bytes_to_save)
                                
                                encrypted_blob = nonce_aes_db + tag_aes_db + ct_aes_db
                                
                                with sqlite3.connect('data.db') as conn:
                                    conn.execute("INSERT INTO user_data (user_id, data_label, encrypted_data) VALUES (?, ?, ?)",
                                                 (st.session_state.user_id, db_label, encrypted_blob))
                                    conn.commit()
                                st.success(f"Data '{db_label}' berhasil dienkripsi AES-GCM dan disimpan!")
                                
                                st.session_state.encrypted_output_bytes = None
                                st.rerun()

                            except Exception as e:
                                st.error(f"Gagal menyimpan ke Brankas: {e}")
                        else:
                            st.warning("Harap masukkan Password Brankas dan Label Data.")

        with col2:
            st.subheader("Dekripsi")
            dec_text_b64 = st.text_area("Hasil (Base64)", height=150, key="dec_text")
            dec_pass = st.text_input("Password Dekripsi", type="password", key="dec_pass")
            dec_v_key = st.text_input("Kunci Vigenère", key="dec_v_key")
            dec_c_shift = st.number_input("Pergeseran Caesar", min_value=1, max_value=25, value=3, key="dec_c_shift")

            st.markdown("---")
            st.write("**Stage 1: Lapisan Klasik (Teks)**")
            classic_choices_dec = st.multiselect("Pilih 0-2 (urutan SAMA saat enkripsi):", ["Caesar", "Vigenère"], key="c_choice_dec")
            
            st.write("**Stage 2: Lapisan Modern (Bytes)**")
            modern_choices_dec = st.multiselect("Pilih 0 atau 1:", ["AES-128-EAX"], key="m_choice_dec")
            st.markdown("---")
            
            if st.button("Dekripsi Teks"):
                if not dec_text_b64 or not dec_pass:
                    st.warning("Harap isi data terenkripsi dan password.")
                elif not classic_choices_dec and not modern_choices_dec:
                    st.error("Pilih minimal 1 algoritma dekripsi.")
                else:
                    try:
                        data = base64.b64decode(dec_text_b64)
                        salt = data[:16]
                        encrypted_data = data[16:]
                        
                        keys = get_encryption_keys(dec_pass, salt, 16)
                        key_aes128 = keys[0:16]
                        
                        processed_data = encrypted_data
                        
                        for choice in reversed(modern_choices_dec):
                            if choice == "AES-128-EAX":
                                nonce_aes128 = processed_data[:16]
                                tag_aes128 = processed_data[16:32]
                                ct_aes128 = processed_data[32:]
                                cipher_aes128 = AES.new(key_aes128, AES.MODE_EAX, mac_len=16, nonce=nonce_aes128)
                                processed_data = cipher_aes128.decrypt_and_verify(ct_aes128, tag_aes128)
                        
                        plain_text_encrypted = processed_data.decode('utf-8')
                        
                        final_text = plain_text_encrypted
                        for choice in reversed(classic_choices_dec):
                            if choice == "Vigenère":
                                if not dec_v_key:
                                    st.error("Kunci Vigenère tidak boleh kosong.")
                                    raise ValueError("Kunci Vigenère kosong")
                                final_text = vigenere_cipher(final_text, dec_v_key, 'decrypt')
                            elif choice == "Caesar":
                                final_text = caesar_cipher(final_text, dec_c_shift, 'decrypt')

                        st.success("Dekripsi Berhasil!")
                        st.text_area("Pesan Asli", final_text, height=150)
                        
                    except (ValueError, KeyError) as e:
                        st.error(f"Dekripsi Gagal. Pastikan password, kunci, dan urutan algoritma benar.")
                    except Exception as e:
                        st.error(f"Error Dekripsi: {e}")

    with tab2:
        st.header("Steganografi LSB (Teks dalam Gambar)")
        st.caption("Metode ini menyembunyikan data di bit terakhir piksel gambar (Lossless).")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Sembunyikan Pesan")
            cover_image = st.file_uploader("Upload Gambar 'Cover'", type=['png', 'bmp']) 
            secret_message = st.text_area("Pesan Rahasia", height=100, key="steg_msg")
            
            if st.button("Sembunyikan"):
                if cover_image and secret_message:
                    try:
                        stego_image_data = hide_lsb(cover_image, secret_message) 
                        st.success("Pesan berhasil disembunyikan!")
                        st.image(stego_image_data, caption="Gambar Stegano (Format PNG)")
                        st.download_button(
                            label="Download Gambar Stegano (.png)",
                            data=stego_image_data,
                            file_name="stegano_image.png",
                            mime="image/png"
                        )
                    except ValueError as e:
                        st.error(f"Error: {e}")
                    except Exception as e:
                        st.error(f"Error saat memproses: {e}")
                else:
                    st.warning("Harap upload gambar dan isi pesan rahasia.")
                    
        with col2:
            st.subheader("Ungkap Pesan")
            stego_image = st.file_uploader("Upload Gambar 'Stegano'", type=['png', 'bmp'], key="steg_img_up")
            
            if st.button("Ungkap"):
                if stego_image:
                    try:
                        revealed_message = reveal_lsb(stego_image) 
                        
                        if revealed_message:
                            st.success("Pesan berhasil diungkap!")
                            st.text_area("Pesan Terungkap", revealed_message, height=100)
                        else:
                            st.warning("Tidak ada pesan tersembunyi yang ditemukan (atau delimiter tidak cocok).")
                    except Exception as e:
                        st.error(f"Error saat memproses gambar: {e}")
                else:
                    st.warning("Harap upload gambar steganografi (format PNG atau BMP).")
                    
    with tab3:
        st.header("Enkripsi File (ChaCha20-Poly1305)")
        st.caption("Menggunakan stream cipher modern ChaCha20-Poly1305.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Enkripsi File")
            file_to_encrypt = st.file_uploader("Upload File", key="file_enc")
            file_enc_pass = st.text_input("Password Enkripsi", type="password", key="file_enc_pass")
            
            if st.button("Enkripsi File"):
                if file_to_encrypt and file_enc_pass:
                    try:
                        file_data = file_to_encrypt.getvalue()
                        
                        keys = get_encryption_keys(file_enc_pass, get_random_bytes(16), 32)
                        key_chacha = keys[0:32]
                        
                        cipher_chacha = ChaCha20_Poly1305.new(key=key_chacha)
                        nonce_chacha = cipher_chacha.nonce
                        ct_chacha, tag_chacha = cipher_chacha.encrypt_and_digest(file_data)
                        
                        output = get_random_bytes(16) + nonce_chacha + tag_chacha + ct_chacha
                        
                        st.success("File berhasil dienkripsi!")
                        st.download_button(
                            label=f"Download File Terenkripsi (.poly)",
                            data=output,
                            file_name=f"{file_to_encrypt.name}.poly",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error Enkripsi File: {e}")
                else:
                    st.warning("Harap upload file dan isi password.")

        with col2:
            st.subheader("Dekripsi File")
            file_to_decrypt = st.file_uploader("Upload File (.poly)", key="file_dec")
            file_dec_pass = st.text_input("Password Dekripsi", type="password", key="file_dec_pass")
            
            if st.button("Dekripsi File"):
                if not file_to_decrypt or not file_dec_pass:
                    st.warning("Harap upload file dan isi password.")
                else:
                    try:
                        encrypted_data = file_to_decrypt.getvalue()
                        
                        salt = encrypted_data[:16]
                        nonce_chacha = encrypted_data[16:28]
                        tag_chacha = encrypted_data[28:44]
                        ct_chacha = encrypted_data[44:]
                        
                        key_chacha = get_encryption_keys(file_dec_pass, salt, 32)
                        
                        cipher_chacha = ChaCha20_Poly1305.new(key=key_chacha, nonce=nonce_chacha)
                        decrypted_data = cipher_chacha.decrypt_and_verify(ct_chacha, tag_chacha)
                        
                        st.success("File berhasil didekripsi!")
                        original_name = file_to_decrypt.name.rsplit('.poly', 1)[0]
                        st.download_button(
                            label=f"Download File Asli ({original_name})",
                            data=decrypted_data,
                            file_name=original_name,
                            mime="application/octet-stream"
                        )
                    except (ValueError, KeyError):
                        st.error("Dekripsi Gagal. Password salah atau file rusak.")
                    except Exception as e:
                        st.error(f"Error Dekripsi File: {e}")
    
    with tab4:
        st.header("🔐 Brankas Data (AES-256-GCM)")
        st.caption("Buka data yang Anda simpan dari 'Super Enkripsi'. Data di sini dienkripsi dengan AES-GCM.")
        
        db_pass_open = st.text_input("Masukkan Password Brankas", type="password", key="db_pass_open")
        
        if not db_pass_open:
            st.info("Masukkan Password Brankas Anda untuk melihat data yang tersimpan.")
        else:
            try:
                key_aes_gcm = get_database_key(db_pass_open)
                
                st.subheader("Buka dari Brankas")
                
                @st.cache_data(ttl=300)
                def get_vault_items(user_id):
                    with sqlite3.connect('data.db') as conn:
                        return conn.execute("SELECT id, data_label FROM user_data WHERE user_id = ?", (user_id,)).fetchall()

                items = get_vault_items(st.session_state.user_id)
                
                if not items:
                    st.write("Brankas Anda masih kosong.")
                else:
                    item_dict = {label: id for id, label in items}
                    selected_label = st.selectbox("Pilih data untuk didekripsi:", options=item_dict.keys())
                    
                    if st.button("Buka & Dekripsi"):
                        item_id = item_dict[selected_label]
                        
                        with sqlite3.connect('data.db') as conn:
                            encrypted_blob = conn.execute("SELECT encrypted_data FROM user_data WHERE id = ?", (item_id,)).fetchone()[0]
                        
                        nonce_aes = encrypted_blob[:16]
                        tag_aes = encrypted_blob[16:32]
                        ct_aes = encrypted_blob[32:]
                        
                        cipher_aes = AES.new(key_aes_gcm, AES.MODE_GCM, nonce=nonce_aes)
                        decrypted_super_encryption_bytes = cipher_aes.decrypt_and_verify(ct_aes, tag_aes)
                        
                        st.success(f"Data '{selected_label}' berhasil didekripsi AES-GCM:")
                        st.info("Data di bawah ini masih terenkripsi dengan 'Super Enkripsi'. Salin dan tempel ke Tab 1 (Dekripsi) untuk membukanya.")
                        st.text_area("Data Terenkripsi (Base64)", base64.b64encode(decrypted_super_encryption_bytes).decode('utf-8'), height=150)

            except (ValueError, KeyError):
                st.error("Gagal membuka Brankas. Password Brankas salah.")
            except Exception as e:
                st.error(f"Error Brankas: {e}")

        st.markdown("---")
        st.subheader("Enkripsi Database")
        st.caption("Data mentah di database (dienkripsi dengan AES-GCM dan ditampilkan sebagai Base64)")
        
        try:
            with sqlite3.connect('data.db') as conn:
                proof_items = conn.execute("SELECT id, data_label, encrypted_data FROM user_data WHERE user_id = ?", (st.session_state.user_id,)).fetchall()
            
            if not proof_items:
                st.info("Tidak ada data di brankas untuk ditampilkan.")
            else:
                for id, label, encrypted_blob in proof_items:
                    with st.container(border=True):
                        st.code(f"ID: {id} | Label: {label}")
                        st.text_area("Ciphertext (Base64)", 
                                     value=base64.b64encode(encrypted_blob).decode('utf-8'), 
                                     height=100, 
                                     disabled=True, 
                                     key=f"proof_{id}")
        except Exception as e:
            st.error(f"Tidak dapat memuat bukti brankas. Pastikan Anda sudah login. Error: {e}")


if __name__ == "__main__":
    init_db()

    if not st.session_state.get('logged_in', False):
        show_login_page()
    else:

        show_main_app()

