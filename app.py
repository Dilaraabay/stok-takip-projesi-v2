"""
import streamlit as st
import pandas as pd

st.title("Stok Takip Sistemi")

try:
    df = pd.read_csv("stok.csv")
except FileNotFoundError:
    df = pd.read_csv("stok_csv")
except FileNotFoundError:
    df = pd.DataFrame(colums=["Ürün Adı","Stok Miktarı", "Kritik Seviye"])
    
st.subheader("Yeni Ürün Ekle")
urun_adi = st.text_input("Ürün Adı")
stok_miktarı = st.number_input("Stok Miktarı", min_value=0, step=1)
kritik_seviye = st.number_input("Kritik seviye", min_value=0, step=1)
if st.button("Ekle"):
    yeni_urun = {"Ürün Adı": urun_adi, "Stok Miktarı": stok_miktarı, "Kritik Seviye": kritik_seviye}
    df = pd.concat([df, pd.DataFrame([yeni_urun])], ignore_index=True)
    df.to_csv("stok.csv", index=False)
    st.success("Ürün eklendi!")
    
st.subheader("Stok Listesi")
st.dataframe(df)

st.subheader("Stok Güncelle")
urunler = df["Ürün Adı"].tolist()
secili_urun = st.selectbox("Ürün Seç", urunler)
yeni_stok = st.number_input("Yeni Stok Miktarı", min_value=0, step=1)

if st.button("Güncelle"):
    df.loc[df["Ürün Adı"] == secili_urun, "Stok Miktarı"] = yeni_stok
    df.to_csv("stok.csv", index = False)
    st.success("Stok güncellendi!")
    
st.subheader("Ürün sil")
sil_urun = st.selectbox("Silinecek Ürün Seç", urunler, key="silme")

if st.button("Sil"):
    df = df[df["Ürün Adı"] != sil_urun]
    df.to_csv("stok.csv", index=False)
    st.success("Ürün silindi!")

st.subheader("Kritik Stoktaki Ürünler")
kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]
st.dataframe(kritik_df)

st.subheader("AI Sipariş Önerisi")

def siparis_oner(row):
    eksik = row["Kritik Seviye"] - row["Stok Miktarı"]
    siparis_miktari = eksik + 10
    return f"{row['Ürün Adı']} için stok düşük. En az {siparis_miktari} adet sipariş ver."

kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]

if kritik_df.empty:
    st.write("Tüm stoklar güvenli seviyede. Sipariş önerisi yok.")
else:
    kritik_df["Sipariş Önerisi"] = kritik_df.apply(siparis_oner, axis=1)
    st.dataframe(kritik_df[["Ürün Adı", "Stok Miktarı", "Kritik Seviye", "Sipariş Önerisi"]])
"""
"""

import streamlit as st
import pandas as pd

st.title("🗂️ Akıllı Stok Takip ve Sipariş Öneri Sistemi")

# Kullanıcıdan dosya yüklemesini iste
uploaded_file = st.file_uploader("Lütfen stok dosyasını yükleyin (CSV)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    st.subheader("Yüklenen Stok Verisi")
    st.dataframe(df)

    # Kritik stok hesapla
    kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]

    st.subheader("🔴 Kritik Stoktaki Ürünler")
    st.dataframe(kritik_df)

    # AI sipariş önerisi
    kritik_df["Sipariş Önerisi"] = kritik_df.apply(
        lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
        axis=1
    )

    st.subheader("🤖 AI Sipariş Önerisi")
    st.dataframe(kritik_df)

    # İndirilebilir CSV
    csv = kritik_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Sonucu İndir (CSV)",
        data=csv,
        file_name="siparis_onerisi.csv",
        mime="text/csv"
    )
    
import matplotlib.pyplot as plt

st.subheader("📊 Stok Durumu Grafiği")

fig, ax = plt.subplots(figsize=(10,5))

kritik = df["Stok Miktarı"] <= df["Kritik Seviye"]
normal = ~kritik

ax.bar(df.loc[normal, "Ürün Adı"], df.loc[normal, "Stok Miktarı"], color='green', label='Güvenli Stok')
ax.bar(df.loc[kritik, "Ürün Adı"], df.loc[kritik, "Stok Miktarı"], color='red', label='Kritik Stok')

plt.xticks(rotation=45)
plt.ylabel("Stok Miktarı")
plt.title("Ürün Bazlı Stok Durumu")
plt.legend()

"""
"""

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# Kullanıcı Girişi
def login():
    st.sidebar.title("🔐 Giriş Paneli")
    username = st.sidebar.text_input("Kullanıcı Adı")
    password = st.sidebar.text_input("Şifre", type="password")

    if st.sidebar.button("Giriş Yap"):
        if username == "admin" and password == "1234":
            st.session_state["login"] = True
        else:
            st.sidebar.error("Hatalı kullanıcı adı veya şifre!")

# Login kontrolü
if "login" not in st.session_state:
    st.session_state["login"] = False

if not st.session_state["login"]:
    login()
    st.stop()

st.title("🗂️ Akıllı Stok Takip ve Sipariş Öneri Sistemi")

uploaded_file = st.file_uploader("Lütfen stok dosyasını yükleyin (CSV)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    st.subheader("Yüklenen Stok Verisi")
    st.dataframe(df)

    kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]
    st.subheader("🔴 Kritik Stoktaki Ürünler")
    st.dataframe(kritik_df)

    kritik_df["Sipariş Önerisi"] = kritik_df.apply(
        lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
        axis=1
    )

    st.subheader("🤖 AI Sipariş Önerisi")
    st.dataframe(kritik_df)

    # İndirilebilir CSV
    csv = kritik_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Sonucu İndir (CSV)",
        data=csv,
        file_name="siparis_onerisi.csv",
        mime="text/csv"
    )

    # GRAFİK BÖLÜMÜ
    st.subheader("📊 Stok Durumu Grafiği")
    fig, ax = plt.subplots(figsize=(10, 5))
    kritik = df["Stok Miktarı"] <= df["Kritik Seviye"]
    normal = ~kritik

    ax.bar(df.loc[normal, "Ürün Adı"], df.loc[normal, "Stok Miktarı"], color='green', label='Güvenli Stok')
    ax.bar(df.loc[kritik, "Ürün Adı"], df.loc[kritik, "Stok Miktarı"], color='red', label='Kritik Stok')

    plt.xticks(rotation=45)
    plt.ylabel("Stok Miktarı")
    plt.title("Ürün Bazlı Stok Durumu")
    plt.legend()
    st.pyplot(fig)

"""
"""
import streamlit as st
import pandas as pd
import uuid
import hashlib
import os
import matplotlib.pyplot as plt

# Kullanıcılar için CSV dosyası
USER_FILE = 'users.csv'

# Kullanıcı dosyası yoksa oluştur
if not os.path.exists(USER_FILE):
    pd.DataFrame(columns=['user_id', 'username', 'password']).to_csv(USER_FILE, index=False)

# Şifreyi hashle (güvenlik için)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Kullanıcı kayıt fonksiyonu
def register_user(username, password):
    users = pd.read_csv(USER_FILE)
    if username in users['username'].values:
        return False  # kullanıcı adı zaten var
    new_user = {
        'user_id': str(uuid.uuid4()),
        'username': username,
        'password': hash_password(password)
    }
    users = pd.concat([users, pd.DataFrame([new_user])], ignore_index=True)
    users.to_csv(USER_FILE, index=False)
    return True

# Kullanıcı doğrulama
def login_user(username, password):
    users = pd.read_csv(USER_FILE)
    hashed_pw = hash_password(password)
    user = users[(users['username'] == username) & (users['password'] == hashed_pw)]
    if not user.empty:
        return user.iloc[0]['user_id']
    else:
        return None

# Giriş paneli
st.title("🧮 AI Destekli Stok Takip Sistemi")
menu = ["Giriş Yap", "Kayıt Ol"]
choice = st.sidebar.selectbox("Menü", menu)

if 'user_id' not in st.session_state:
    st.session_state['user_id'] = None

if choice == "Kayıt Ol":
    st.subheader("Yeni Kullanıcı Kaydı")
    new_user = st.text_input("Kullanıcı Adı")
    new_pass = st.text_input("Şifre", type='password')
    if st.button("Kayıt Ol"):
        if register_user(new_user, new_pass):
            st.success("Kayıt başarılı! Giriş yapabilirsiniz.")
        else:
            st.error("Bu kullanıcı adı zaten kayıtlı.")

elif choice == "Giriş Yap":
    st.subheader("Giriş")
    username = st.text_input("Kullanıcı Adı")
    password = st.text_input("Şifre", type='password')
    if st.button("Giriş Yap"):
        user_id = login_user(username, password)
        if user_id:
            st.session_state['user_id'] = user_id
            st.session_state['username'] = username
            st.success("Giriş başarılı!")
        else:
            st.error("Hatalı kullanıcı adı veya şifre")

# Giriş başarılıysa esas uygulama çalışsın
if st.session_state['user_id']:
    st.subheader(f"Hoşgeldin {st.session_state['username']}! Artık stok verilerini yükleyebilirsin.")
    uploaded_file = st.file_uploader("📁 Stok dosyanızı yükleyin (CSV)", type=["csv"])

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.subheader("📊 Yüklenen Stok Verisi")
            st.dataframe(df)

            if 'Ürün Adı' not in df.columns or 'Stok Miktarı' not in df.columns or 'Kritik Seviye' not in df.columns:
                st.error("CSV dosyanızda 'Ürün Adı', 'Stok Miktarı' ve 'Kritik Seviye' başlıkları olmalı!")
            else:
                kritik_df = df[df['Stok Miktarı'] <= df['Kritik Seviye']]

                st.subheader("🔴 Kritik Stoktaki Ürünler")
                st.dataframe(kritik_df)

                kritik_df["Sipariş Önerisi"] = kritik_df.apply(
                    lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
                    axis=1
                )

                st.subheader("🤖 AI Sipariş Önerisi")
                st.dataframe(kritik_df)

                # CSV indir
                csv = kritik_df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 AI Sipariş Önerilerini İndir", data=csv, file_name='siparis_onerisi.csv', mime='text/csv')

                # Grafik çizimi
                st.subheader("📊 Stok Durumu Grafiği")
                fig, ax = plt.subplots(figsize=(10, 5))
                kritik = df["Stok Miktarı"] <= df["Kritik Seviye"]
                normal = ~kritik
                ax.bar(df.loc[normal, "Ürün Adı"], df.loc[normal, "Stok Miktarı"], color='green', label='Güvenli Stok')
                ax.bar(df.loc[kritik, "Ürün Adı"], df.loc[kritik, "Stok Miktarı"], color='red', label='Kritik Stok')
                plt.xticks(rotation=45)
                plt.ylabel("Stok Miktarı")
                plt.title("Ürün Bazlı Stok Durumu")
                plt.legend()
                st.pyplot(fig)

        except Exception as e:
            st.error(f"Dosya okunurken hata oluştu: {e}")
    else:
        st.warning("Lütfen CSV dosyanızı yükleyin.")

"""
"""
import streamlit as st
import pandas as pd
import json
import os

# Kullanıcı verisini yönetmek için yardımcı fonksiyonlar

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                users = {}
    else:
        users = {}
    return users

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# Kullanıcı kayıt işlemi
def register():
    st.title("📝 AI Destekli Stok Takip Sistemi - Kayıt")
    kullanici = st.text_input("Kullanıcı Adı")
    sifre = st.text_input("Şifre", type="password")
    if st.button("Kayıt Ol"):
        users = load_users()
        if kullanici in users:
            st.error("Bu kullanıcı adı zaten kayıtlı.")
        else:
            users[kullanici] = sifre
            save_users(users)
            st.success("Kayıt başarılı! Otomatik giriş yapılıyor...")
            st.session_state["authenticated"] = True
            st.session_state["user"] = kullanici
            st.rerun()

# Kullanıcı giriş işlemi
def login():
    st.title("🔐 AI Destekli Stok Takip Sistemi - Giriş")
    kullanici = st.text_input("Kullanıcı Adı")
    sifre = st.text_input("Şifre", type="password")
    if st.button("Giriş Yap"):
        users = load_users()
        if kullanici in users and users[kullanici] == sifre:
            st.success("Giriş başarılı!")
            st.session_state["authenticated"] = True
            st.session_state["user"] = kullanici
            st.rerun()
        else:
            st.error("Kullanıcı adı veya şifre hatalı.")

# Stok takip ve analiz modülü
def stock_page():
    st.title("📦 AI Destekli Stok Takip Sistemi")

    uploaded_file = st.file_uploader("Lütfen stok dosyasını yükleyin (CSV)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.subheader("📊 Yüklenen Stok Verisi")
        st.dataframe(df)

        kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]

        st.subheader("🔴 Kritik Stoktaki Ürünler")
        st.dataframe(kritik_df)

        kritik_df["Sipariş Önerisi"] = kritik_df.apply(
            lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
            axis=1
        )

        st.subheader("🤖 AI Sipariş Önerisi")
        st.dataframe(kritik_df[["Ürün Adı", "Stok Miktarı", "Kritik Seviye", "Sipariş Önerisi"]])

        # CSV olarak indirme butonu
        csv = kritik_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 İndirilebilir CSV", data=csv, file_name="siparis_onerisi.csv", mime='text/csv')

    if st.button("Çıkış Yap"):
        st.session_state["authenticated"] = False
        st.session_state["user"] = None
        st.rerun()

# Ana uygulama akışı

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    secim = st.sidebar.radio("Menü", ["Giriş Yap", "Kayıt Ol"])

    if secim == "Giriş Yap":
        login()
    else:
        register()
else:
    stock_page()

"""
"""
import streamlit as st
import pandas as pd
import json
import os

# Kullanıcı verisi için dosya
USERS_FILE = "users.json"

# Kullanıcıları yükle

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                users = {}
    else:
        users = {}
    return users

# Kullanıcıları kaydet

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# Kayıt işlemi

def register():
    st.title("📝 AI Destekli Stok Takip Sistemi - Kayıt")
    kullanici = st.text_input("Kullanıcı Adı")
    sifre = st.text_input("Şifre", type="password")
    if st.button("Kayıt Ol"):
        users = load_users()
        if kullanici in users:
            st.error("Bu kullanıcı adı zaten kayıtlı.")
        else:
            users[kullanici] = sifre
            save_users(users)
            st.success("Kayıt başarılı! Otomatik giriş yapılıyor...")
            st.session_state["authenticated"] = True
            st.session_state["user"] = kullanici
            st.rerun()

# Giriş işlemi

def login():
    st.title("🔐 AI Destekli Stok Takip Sistemi - Giriş")
    kullanici = st.text_input("Kullanıcı Adı")
    sifre = st.text_input("Şifre", type="password")
    if st.button("Giriş Yap"):
        users = load_users()
        if kullanici in users and users[kullanici] == sifre:
            st.success("Giriş başarılı!")
            st.session_state["authenticated"] = True
            st.session_state["user"] = kullanici
            st.rerun()
        else:
            st.error("Kullanıcı adı veya şifre hatalı.")

# Stok takip modülü

def stock_page():
    st.title("📦 AI Destekli Stok Takip Sistemi")
    st.write(f"Hoşgeldin **{st.session_state['user']}**")

    uploaded_file = st.file_uploader("Lütfen stok dosyasını yükleyin (CSV)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        df.columns = df.columns.str.strip()
        st.subheader("📊 Yüklenen Stok Verisi")
        st.dataframe(df)

        kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]
        st.subheader("🔴 Kritik Stoktaki Ürünler")
        st.dataframe(kritik_df)

        kritik_df["Sipariş Önerisi"] = kritik_df.apply(
            lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
            axis=1
        )

        st.subheader("🤖 AI Sipariş Önerisi")
        st.dataframe(kritik_df[["Ürün Adı", "Stok Miktarı", "Kritik Seviye", "Sipariş Önerisi"]])

        csv = kritik_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 İndirilebilir CSV", data=csv, file_name="siparis_onerisi.csv", mime='text/csv')

    if st.button("Çıkış Yap"):
        st.session_state["authenticated"] = False
        st.session_state["user"] = None
        st.rerun()

# Uygulama akışı

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    secim = st.sidebar.radio("Menü", ["Giriş Yap", "Kayıt Ol"])

    if secim == "Giriş Yap":
        login()
    else:
        register()
else:
    stock_page()
"""
import streamlit as st
import pandas as pd
import os
import hashlib

# Kullanıcı verisi dosyası
USER_CSV = "users.csv"

# Kullanıcı kayıt ve doğrulama işlemleri
def load_users():
    if os.path.exists(USER_CSV):
        return pd.read_csv(USER_CSV)
    else:
        return pd.DataFrame(columns=["username", "password"])

def save_user(username, password):
    users = load_users()
    users = pd.concat([users, pd.DataFrame([[username, password]], columns=["username", "password"])], ignore_index=True)
    users.to_csv(USER_CSV, index=False)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_login(username, password):
    users = load_users()
    hashed = hash_password(password)
    return not users[(users['username'] == username) & (users['password'] == hashed)].empty

# Giriş ve kayıt akışı
def login_screen():
    st.title("🚀 AI Destekli Stok Takip Sistemi")

    menu = ["Giriş Yap", "Kayıt Ol"]
    choice = st.sidebar.radio("Menü", menu)

    if choice == "Giriş Yap":
        st.subheader("Giriş Yap")
        username = st.text_input("Kullanıcı Adı")
        password = st.text_input("Şifre", type="password")
        if st.button("Giriş"):
            if validate_login(username, password):
                st.success(f"Hoş geldin {username} 🎉")
                st.session_state['user'] = username
            else:
                st.error("Hatalı kullanıcı adı veya şifre.")
    else:
        st.subheader("Kayıt Ol")
        username = st.text_input("Kullanıcı Adı", key="register_username")
        password = st.text_input("Şifre", type="password", key="register_password")
        if st.button("Kayıt Ol"):
            users = load_users()
            if username in users['username'].values:
                st.warning("Bu kullanıcı adı zaten kayıtlı.")
            else:
                save_user(username, hash_password(password))
                st.success("Kayıt başarılı! Giriş yapabilirsiniz.")

# Stok takip ve AI öneri ekranı
def stock_screen():
    st.title("📊 Stok Takip ve Sipariş Öneri Sistemi")

    uploaded_file = st.file_uploader("📂 Stok dosyanızı yükleyin (CSV formatında)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.write("📦 Yüklenen Veriler:")
        st.dataframe(df)

        kritik_df = df[df["Stok Miktarı"] <= df["Kritik Seviye"]]
        st.write("⚠ Kritik Stoktaki Ürünler:")
        st.dataframe(kritik_df)

        kritik_df["Sipariş Önerisi"] = kritik_df.apply(
            lambda row: f"{row['Ürün Adı']} için stok düşük. En az {row['Kritik Seviye'] - row['Stok Miktarı']} adet sipariş ver.",
            axis=1
        )
        st.write("🤖 AI Sipariş Önerileri:")
        st.dataframe(kritik_df[["Ürün Adı", "Stok Miktarı", "Kritik Seviye", "Sipariş Önerisi"]])

# Oturum kontrolü
if 'user' not in st.session_state:
    login_screen()
else:
    stock_screen()



    