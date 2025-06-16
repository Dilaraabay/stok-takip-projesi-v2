import streamlit as st
import pandas as pd
import json
import os

# Logo ve stil
st.set_page_config(page_title="LUMA AI Stok Takip", page_icon="🧠", layout="centered")
st.markdown(
    """
    <style>
    body {background-color: #f5f7fa;}
    .stApp {background-color: #f5f7fa;}
    .title {font-size:40px; font-weight:bold; color:#273746;}
    .subtitle {font-size:24px; color:#5D6D7E;}
    </style>
    """, unsafe_allow_html=True
)

# Logo göster
st.image("logo.png", width=200)
st.markdown("<p class='title'>LUMA AI Stok Takip Sistemi</p>", unsafe_allow_html=True)
st.markdown("<p class='subtitle'>Akıllı Stok ve Sipariş Öneri Platformu</p>", unsafe_allow_html=True)

# Kullanıcı dosyası
USER_FILE = "users.json"
if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        json.dump({}, f)

def load_users():
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

# Kayıt ve Giriş Sistemi
menu = st.sidebar.radio("Menü", ["Giriş Yap", "Kayıt Ol"])

if menu == "Kayıt Ol":
    st.subheader("Yeni Kullanıcı Kaydı")
    new_user = st.text_input("Kullanıcı Adı")
    new_pass = st.text_input("Şifre", type="password")
    if st.button("Kayıt Ol"):
        users = load_users()
        if new_user in users:
            st.error("Bu kullanıcı adı zaten mevcut.")
        else:
            users[new_user] = new_pass
            save_users(users)
            st.success("Kayıt başarılı! Giriş yapabilirsiniz.")

elif menu == "Giriş Yap":
    st.subheader("Giriş Yap")
    user = st.text_input("Kullanıcı Adı")
    password = st.text_input("Şifre", type="password")
    if st.button("Giriş"):
        users = load_users()
        if user in users and users[user] == password:
            st.success(f"Hoş geldin {user} 👋")

            # Kullanıcı giriş yaptıktan sonra stok paneli
            st.header("📦 Stok Dosyası Yükle")
            uploaded_file = st.file_uploader("Lütfen stok CSV dosyasını yükleyin", type=["csv"])
            if uploaded_file is not None:
                df = pd.read_csv(uploaded_file)
                st.write("Yüklenen Veri:")
                st.dataframe(df)

                kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]
                st.warning("Kritik stokta olan ürünler:")
                st.dataframe(kritik_df)

                kritik_df["Sipariş Önerisi"] = kritik_df.apply(
                    lambda row: f"{row['Ürün Adı']} için {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş verin.", axis=1)
                st.success("📦 Sipariş Önerileri:")
                st.dataframe(kritik_df[["Ürün Adı", "Sipariş Önerisi"]])
        else:
            st.error("Kullanıcı adı veya şifre yanlış.")
    
