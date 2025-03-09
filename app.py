import streamlit as st
import base64
import hashlib
import hmac
import time
import random
import io
import json
import matplotlib.pyplot as plt
import numpy as np

# Import des modules de PyCryptodome pour la cryptographie moderne
from Crypto.Cipher import AES, ARC4, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

###########################################
# Fonctions pour la Cryptographie Ancienne #
###########################################

# --- Chiffre de César ---
def caesar_cipher(text, shift, mode='encrypt'):
    """
    Chiffre ou déchiffre un texte avec le chiffre de César.
    
    Pour chaque lettre alphabétique, le chiffrement consiste à décaler
    sa position dans l'alphabet d'un certain nombre (shift). Pour le déchiffrer,
    on inverse le décalage.
    
    Exemples :
      - Avec un shift de 3, 'A' devient 'D', 'B' devient 'E', etc.
      - En mode décryptage, 'D' redevient 'A'.
    
    :param text: Le texte à traiter.
    :param shift: Le nombre de positions de décalage.
    :param mode: 'encrypt' pour chiffrer, 'decrypt' pour déchiffrer.
    :return: Le texte chiffré ou déchiffré.
    """
    result = ''
    # Pour chaque caractère, si c'est une lettre, on décale selon le shift
    for char in text:
        if char.isalpha():
            # Détermine la base selon si la lettre est majuscule ou minuscule
            base = 65 if char.isupper() else 97
            # Décalage positif pour chiffrement, négatif pour déchiffrement
            shift_val = shift if mode == 'encrypt' else -shift
            result += chr((ord(char) - base + shift_val) % 26 + base)
        else:
            result += char
    return result

# --- Chiffre Atbash ---
def atbash_cipher(text):
    """
    Chiffre Atbash : substitution alphabétique inversée.
    
    Cet algorithme remplace chaque lettre par son "miroir" dans l'alphabet :
      - A devient Z, B devient Y, C devient X, etc.
    
    Il s'agit d'une méthode de substitution simple sans clé et historiquement utilisée.
    
    :param text: Le texte à chiffrer.
    :return: Le texte chiffré.
    """
    result = ''
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            # Calcule l'indice inversé dans l'alphabet
            result += chr(25 - (ord(char) - base) + base)
        else:
            result += char
    return result

# --- Chiffre de Vigenère ---
def vigenere_cipher(text, key, mode='encrypt'):
    """
    Chiffre de Vigenère.
    
    Algorithme polyalphabétique qui utilise une clé répétée pour
    décaler chaque lettre du texte. Le décalage est défini par la position
    de la lettre correspondante dans la clé.
    
    - En chiffrement, chaque lettre du texte est décalée vers la droite.
    - En déchiffrement, le décalage est inversé.
    
    :param text: Le texte à traiter.
    :param key: La clé (chaîne de caractères).
    :param mode: 'encrypt' pour chiffrer, 'decrypt' pour déchiffrer.
    :return: Le texte chiffré ou déchiffré.
    """
    result = ''
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shift = ord(key[key_index % len(key)]) - 97
            shift_val = shift if mode == 'encrypt' else -shift
            result += chr((ord(char) - base + shift_val) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

# --- Méthode de pliage (Folding Cipher) ---
def folding_cipher(text):
    """
    Méthode de pliage :
    
    Cette méthode consiste à diviser le texte en deux moitiés,
    inverser la seconde moitié, puis intercaler les caractères des deux parties.
    Cela permet d'obscurcir légèrement le message, bien que ce ne soit pas une méthode sécurisée.
    
    :param text: Le texte à traiter.
    :return: Le texte transformé.
    """
    mid = len(text) // 2
    first_half = text[:mid]
    second_half = text[mid:]
    second_half = second_half[::-1]  # Inversion de la seconde moitié
    result = ''
    # Intercaler les caractères des deux moitiés
    for i in range(max(len(first_half), len(second_half))):
        if i < len(first_half):
            result += first_half[i]
        if i < len(second_half):
            result += second_half[i]
    return result

###########################################
# Fonctions pour la Cryptographie Moderne  #
###########################################

# --- AES (Advanced Encryption Standard) ---
def aes_encrypt(plaintext, key):
    """
    Chiffrement AES en mode CBC.
    
    AES est un algorithme de chiffrement symétrique qui chiffre le texte en blocs.
    Ici, on utilise le mode CBC (Cipher Block Chaining).
    
    - La clé fournie est d'abord passée dans un hash SHA-256, puis les 16 premiers octets sont utilisés.
    - Un vecteur d'initialisation (IV) aléatoire de 16 octets est généré pour rendre le chiffrement unique.
    - Le texte est "paddé" pour respecter la taille de bloc requise.
    - Le résultat est la concaténation de l'IV et du texte chiffré, encodé en base64.
    
    :param plaintext: Le texte en clair.
    :param key: La clé utilisée pour le chiffrement.
    :return: Le texte chiffré en base64.
    """
    # Préparation de la clé
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()[:16]
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext_b64, key):
    """
    Déchiffrement AES en mode CBC.
    
    Le processus inverse consiste à :
      - Convertir le texte en base64 en octets.
      - Extraire le vecteur d'initialisation (IV) des premiers 16 octets.
      - Déchiffrer le reste pour récupérer le texte en clair après suppression du padding.
    
    :param ciphertext_b64: Le texte chiffré encodé en base64.
    :param key: La clé utilisée pour le chiffrement.
    :return: Le texte déchiffré.
    """
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()[:16]
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

# --- RC4 ---
def rc4_encrypt(plaintext, key):
    """
    Chiffrement RC4.
    
    RC4 est un algorithme de chiffrement par flot qui génère une séquence
    de bits pseudo-aléatoire à partir d'une clé. Ce flux est ensuite combiné
    avec le texte en clair par une opération XOR pour produire le texte chiffré.
    
    :param plaintext: Le texte en clair.
    :param key: La clé de chiffrement.
    :return: Le texte chiffré en base64.
    """
    key_bytes = key.encode('utf-8')
    cipher = ARC4.new(key_bytes)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rc4_decrypt(ciphertext_b64, key):
    """
    Déchiffrement RC4.
    
    Le même algorithme RC4 est utilisé en inversant le processus de chiffrement.
    
    :param ciphertext_b64: Le texte chiffré en base64.
    :param key: La clé de chiffrement.
    :return: Le texte en clair.
    """
    key_bytes = key.encode('utf-8')
    cipher = ARC4.new(key_bytes)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8', errors='ignore')

# --- RSA ---
def generate_rsa_keys():
    """
    Génère une paire de clés RSA de 2048 bits.
    
    RSA est un algorithme asymétrique qui repose sur la difficulté de
    factoriser de grands nombres. La génération de clés consiste à
    créer une clé publique (pour chiffrer ou vérifier une signature)
    et une clé privée (pour déchiffrer ou signer).
    
    :return: Un tuple (clé_publique, clé_privée) sous forme d’octets.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def rsa_encrypt(plaintext, public_key):
    """
    Chiffrement RSA avec la clé publique.
    
    Utilise le schéma PKCS1_OAEP qui ajoute du padding pour une meilleure sécurité.
    
    :param plaintext: Le texte en clair.
    :param public_key: La clé publique en bytes ou chaîne.
    :return: Le texte chiffré encodé en base64.
    """
    pub_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(pub_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext_b64, private_key):
    """
    Déchiffrement RSA avec la clé privée.
    
    Le déchiffrement consiste à utiliser la clé privée pour retrouver le
    texte en clair à partir du texte chiffré.
    
    :param ciphertext_b64: Le texte chiffré encodé en base64.
    :param private_key: La clé privée en bytes ou chaîne.
    :return: Le texte en clair.
    """
    priv_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(priv_key)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def rsa_sign(message, private_key):
    """
    Génère une signature numérique RSA pour un message.
    
    La signature est réalisée en calculant le hash SHA-256 du message,
    puis en signant ce hash avec la clé privée via le schéma PKCS1_v1.5.
    
    :param message: Le message à signer.
    :param private_key: La clé privée.
    :return: La signature encodée en base64.
    """
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def rsa_verify(message, signature, public_key):
    """
    Vérifie la signature RSA d'un message.
    
    En recalculant le hash du message et en utilisant la clé publique,
    on peut vérifier si la signature correspond bien à celle générée
    par la clé privée associée.
    
    :param message: Le message signé.
    :param signature: La signature à vérifier (base64).
    :param public_key: La clé publique.
    :return: True si la signature est valide, False sinon.
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

# --- Diffie-Hellman (Simulation) ---
def diffie_hellman_demo(p, g, private_a, private_b):
    """
    Simule l'échange de clés Diffie-Hellman entre deux parties.
    
    Les deux utilisateurs (A et B) partagent des paramètres publics :
      - p : un nombre premier
      - g : une base (générateur)
    
    Chaque utilisateur choisit une clé privée (secret) et calcule
    sa clé publique. Ensuite, en échangeant ces clés publiques,
    ils peuvent chacun calculer une clé partagée qui sera identique.
    
    :param p: Le nombre premier.
    :param g: Le générateur.
    :param private_a: La clé privée de A.
    :param private_b: La clé privée de B.
    :return: Les clés publiques de A et B, ainsi que la clé partagée calculée par chacun.
    """
    public_a = pow(g, private_a, p)
    public_b = pow(g, private_b, p)
    shared_a = pow(public_b, private_a, p)
    shared_b = pow(public_a, private_b, p)
    return public_a, public_b, shared_a, shared_b

# --- Fonctions de Hachage ---
def hash_md5(text):
    """
    Calcule le hachage MD5 d'un texte.
    
    MD5 est une fonction de hachage rapide, mais considérée comme peu sécurisée pour la cryptographie.
    """
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def hash_sha256(text):
    """
    Calcule le hachage SHA-256 d'un texte.
    
    SHA-256 offre une meilleure sécurité et est largement utilisé pour vérifier l'intégrité des données.
    """
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def hash_sha512(text):
    """
    Calcule le hachage SHA-512 d'un texte.
    
    SHA-512 fournit un hachage de 512 bits et est utilisé lorsque l'on souhaite une empreinte plus longue.
    """
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def generate_mac(text, key):
    """
    Génère un MAC (Message Authentication Code) en utilisant HMAC avec SHA-256.
    
    Le MAC permet de vérifier l'authenticité et l'intégrité d'un message en combinant une clé secrète
    avec le contenu du message.
    
    :param text: Le message.
    :param key: La clé secrète.
    :return: Le MAC sous forme hexadécimale.
    """
    return hmac.new(key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256).hexdigest()

# --- Stockage sécurisé de mot de passe (avec sel) ---
def hash_password(password):
    """
    Hash un mot de passe en ajoutant un sel aléatoire et en utilisant la fonction PBKDF2_HMAC (SHA-256).
    
    Le sel permet d'éviter les attaques par tables arc-en-ciel en rendant chaque hachage unique même pour
    des mots de passe identiques.
    
    :param password: Le mot de passe en clair.
    :return: Une chaîne contenant le sel et le hash séparés par ':'.
    """
    salt = get_random_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + hashed.hex()

###########################################
# Interface Streamlit                     #
###########################################

# Barre latérale pour la navigation entre les sections du projet
st.sidebar.title("Navigation")
section = st.sidebar.selectbox(
    "Choisissez la section", 
    [
        "Introduction à la Cryptographie",
        "Cryptographie Ancienne",
        "Cryptographie Moderne",
        "Implémentation des Algorithmes",
        "Comparaison des Algorithmes",
        "Applications Pratiques"
    ]
)

# Contenu principal
###########################################
# 1. Introduction à la Cryptographie      #
###########################################
if section == "Introduction à la Cryptographie":
    st.title("Introduction à la Cryptographie")
    # Ajout de la mention de l'auteur et de l'objectif pédagogique
    st.write("**Projet réalisé par Salmane Koraichi pour des fins pédagogiques.**")
    st.write("""
    La cryptographie est l'art de protéger les informations en les transformant de façon à ce qu'elles soient 
    inintelligibles pour toute personne non autorisée. Elle repose sur des algorithmes qui transforment un message 
    en clair en un message chiffré et vice versa. Cette application permet de découvrir et d'expérimenter avec 
    divers algorithmes allant des méthodes classiques (comme le chiffre de César ou Atbash) aux méthodes modernes 
    (telles que AES, RSA et Diffie-Hellman).
    """)

###########################################
# 2. Cryptographie Ancienne               #
###########################################
elif section == "Cryptographie Ancienne":
    st.title("Cryptographie Ancienne")
    st.markdown("""
    **Explications détaillées :**
    
    - **Chiffre de César** : Un algorithme de substitution simple où chaque lettre du message est décalée d'un nombre fixe de positions dans l'alphabet.
    - **Chiffre Atbash** : Remplace chaque lettre par son opposé dans l'alphabet (A ↔ Z, B ↔ Y, ...).
    - **Chiffre de Vigenère** : Utilise une clé pour effectuer plusieurs substitutions ; chaque lettre est décalée selon la lettre correspondante de la clé.
    - **Méthode de pliage** : Divise le texte en deux, inverse la seconde moitié et intercale les caractères, illustrant une transformation simple.
    """)
    cipher_choice = st.radio(
        "Choisissez l'algorithme ancien",
        ("Chiffre de César", "Chiffre Atbash", "Chiffre de Vigenère", "Méthode de pliage")
    )
    if cipher_choice == "Chiffre de César":
        st.subheader("Chiffre de César")
        st.info("""
        **Comment ça marche ?**
        - Chaque lettre du texte est transformée en décalant sa position dans l'alphabet.
        - Par exemple, avec un décalage de 3 : A → D, B → E, etc.
        - Pour déchiffrer, le décalage est inversé.
        """)
        text = st.text_area("Entrez le texte")
        shift = st.number_input("Décalage", min_value=0, max_value=25, value=3)
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"))
        if st.button("Exécuter"):
            result = caesar_cipher(text, shift, mode.lower())
            st.write("Résultat :", result)
    elif cipher_choice == "Chiffre Atbash":
        st.subheader("Chiffre Atbash")
        st.info("""
        **Comment ça marche ?**
        - Chaque lettre est remplacée par sa lettre opposée dans l'alphabet.
        - A devient Z, B devient Y, etc.
        """)
        text = st.text_area("Entrez le texte")
        if st.button("Exécuter"):
            result = atbash_cipher(text)
            st.write("Résultat :", result)
    elif cipher_choice == "Chiffre de Vigenère":
        st.subheader("Chiffre de Vigenère")
        st.info("""
        **Comment ça marche ?**
        - Un algorithme polyalphabétique qui utilise une clé.
        - La clé est répétée pour couvrir la longueur du message.
        - Chaque lettre est décalée selon la valeur de la lettre correspondante dans la clé.
        """)
        text = st.text_area("Entrez le texte")
        key = st.text_input("Clé")
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"))
        if st.button("Exécuter"):
            result = vigenere_cipher(text, key, mode.lower())
            st.write("Résultat :", result)
    elif cipher_choice == "Méthode de pliage":
        st.subheader("Méthode de pliage")
        st.info("""
        **Comment ça marche ?**
        - Le texte est divisé en deux parties.
        - La seconde partie est inversée.
        - Les caractères des deux parties sont ensuite intercalés.
        """)
        text = st.text_area("Entrez le texte")
        if st.button("Exécuter"):
            result = folding_cipher(text)
            st.write("Résultat :", result)

###########################################
# 3. Cryptographie Moderne                #
###########################################
elif section == "Cryptographie Moderne":
    st.title("Cryptographie Moderne")
    st.markdown("""
    **Explications détaillées :**
    
    - **AES** : Algorithme de chiffrement symétrique en mode bloc (ici CBC). Il utilise une clé fixe et un vecteur d'initialisation pour chiffrer des blocs de données.
    - **RC4** : Algorithme de chiffrement par flot qui génère une séquence pseudo-aléatoire pour combiner avec le texte.
    - **RSA** : Algorithme asymétrique qui utilise une paire de clés (publique et privée) pour chiffrer et déchiffrer, ainsi que pour signer des messages.
    - **Diffie-Hellman** : Protocole d'échange de clé permettant à deux parties de partager une clé secrète sur un canal non sécurisé.
    - **Fonctions de Hachage** : Génèrent une empreinte unique d’un texte pour vérifier son intégrité.
    """)
    modern_choice = st.radio(
        "Choisissez l'algorithme moderne",
        ("AES", "RC4", "RSA", "Diffie-Hellman", "Fonctions de Hachage")
    )
    if modern_choice == "AES":
        st.subheader("AES (Advanced Encryption Standard)")
        st.info("""
        **Comment ça marche ?**
        - AES chiffre le texte en le divisant en blocs.
        - La clé est dérivée via SHA-256 (on prend 16 octets).
        - Un vecteur d'initialisation (IV) est généré aléatoirement pour chaque chiffrement.
        - Le mode CBC est utilisé pour enchaîner les blocs.
        """)
        text = st.text_area("Entrez le texte")
        key = st.text_input("Clé")
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"))
        if st.button("Exécuter AES"):
            if mode == "Encrypt":
                result = aes_encrypt(text, key)
                st.write("Texte chiffré :", result)
            else:
                try:
                    result = aes_decrypt(text, key)
                    st.write("Texte déchiffré :", result)
                except Exception as e:
                    st.error("Erreur lors du déchiffrement : " + str(e))
    elif modern_choice == "RC4":
        st.subheader("RC4")
        st.info("""
        **Comment ça marche ?**
        - RC4 est un algorithme de chiffrement par flot.
        - Il génère une séquence pseudo-aléatoire basée sur la clé.
        - Le texte en clair est combiné avec cette séquence via XOR pour obtenir le texte chiffré.
        """)
        text = st.text_area("Entrez le texte")
        key = st.text_input("Clé")
        mode = st.selectbox("Mode", ("Encrypt", "Decrypt"))
        if st.button("Exécuter RC4"):
            if mode == "Encrypt":
                result = rc4_encrypt(text, key)
                st.write("Texte chiffré :", result)
            else:
                try:
                    result = rc4_decrypt(text, key)
                    st.write("Texte déchiffré :", result)
                except Exception as e:
                    st.error("Erreur lors du déchiffrement : " + str(e))
    elif modern_choice == "RSA":
        st.subheader("RSA")
        st.info("""
        **Explications :**
        - **Génération de clés** : Crée une paire de clés (publique et privée). La clé publique sert au chiffrement ou à la vérification de signature, et la clé privée au déchiffrement ou à la signature.
        - **Chiffrement/Déchiffrement** : Utilise le schéma PKCS1_OAEP pour une sécurité accrue.
        - **Signature** : Le message est signé en calculant son hash (SHA-256) et en le signant avec la clé privée.
        """)
        rsa_choice = st.radio("RSA Options", ("Générer Clés", "Chiffrement/Déchiffrement", "Signature"))
        if rsa_choice == "Générer Clés":
            if st.button("Générer clés RSA"):
                public_key, private_key = generate_rsa_keys()
                st.text_area("Clé Publique", public_key.decode() if isinstance(public_key, bytes) else public_key, height=150)
                st.text_area("Clé Privée", private_key.decode() if isinstance(private_key, bytes) else private_key, height=150)
        elif rsa_choice == "Chiffrement/Déchiffrement":
            text = st.text_area("Entrez le texte")
            key_input = st.text_area("Entrez la clé publique (pour chiffrement) ou la clé privée (pour déchiffrement)", height=150)
            mode = st.selectbox("Mode", ("Encrypt", "Decrypt"))
            if st.button("Exécuter RSA"):
                if mode == "Encrypt":
                    result = rsa_encrypt(text, key_input)
                    st.write("Texte chiffré :", result)
                else:
                    try:
                        result = rsa_decrypt(text, key_input)
                        st.write("Texte déchiffré :", result)
                    except Exception as e:
                        st.error("Erreur lors du déchiffrement : " + str(e))
        elif rsa_choice == "Signature":
            text = st.text_area("Entrez le message")
            private_key_input = st.text_area("Entrez la clé privée pour signer", height=150)
            if st.button("Signer"):
                signature = rsa_sign(text, private_key_input)
                st.write("Signature :", signature)
            public_key_input = st.text_area("Entrez la clé publique pour vérifier", height=150)
            signature_input = st.text_input("Entrez la signature")
            if st.button("Vérifier"):
                valid = rsa_verify(text, signature_input, public_key_input)
                if valid:
                    st.success("La signature est valide")
                else:
                    st.error("Signature invalide")
    elif modern_choice == "Diffie-Hellman":
        st.subheader("Diffie-Hellman")
        st.info("""
        **Comment ça marche ?**
        - Diffie-Hellman permet à deux parties d'établir une clé secrète partagée.
        - Les deux parties conviennent d'un nombre premier p et d'une base g.
        - Chacune choisit une clé privée et calcule sa clé publique.
        - En échangeant leurs clés publiques, elles calculent ensuite une clé partagée identique.
        """)
        # Paramètres (exemple pédagogique)
        p = 23
        g = 5
        st.write(f"Paramètres : p = {p}, g = {g}")
        private_a = st.number_input("Clé privée de A", min_value=1, value=6)
        private_b = st.number_input("Clé privée de B", min_value=1, value=15)
        if st.button("Calculer Diffie-Hellman"):
            public_a, public_b, shared_a, shared_b = diffie_hellman_demo(p, g, private_a, private_b)
            st.write(f"Clé publique de A : {public_a}")
            st.write(f"Clé publique de B : {public_b}")
            st.write(f"Clé partagée (calculée par A) : {shared_a}")
            st.write(f"Clé partagée (calculée par B) : {shared_b}")
    elif modern_choice == "Fonctions de Hachage":
        st.subheader("Fonctions de Hachage")
        st.info("""
        **Comment ça marche ?**
        - Les fonctions de hachage (MD5, SHA-256, SHA-512) transforment un texte en une empreinte unique.
        - Elles sont utilisées pour vérifier l'intégrité des données.
        - HMAC combine une clé secrète avec le message pour fournir une authentification.
        """)
        text = st.text_area("Entrez le texte")
        if st.button("Calculer les hachages"):
            st.write("MD5 :", hash_md5(text))
            st.write("SHA-256 :", hash_sha256(text))
            st.write("SHA-512 :", hash_sha512(text))
        key = st.text_input("Clé pour MAC")
        if st.button("Générer MAC"):
            st.write("MAC (HMAC SHA256) :", generate_mac(text, key))

###########################################
# 4. Implémentation des Algorithmes        #
###########################################
elif section == "Implémentation des Algorithmes":
    st.title("Implémentation des Algorithmes")
    st.write("Ci-dessous, le code détaillé de quelques algorithmes utilisés dans cette application :")
    st.code(
r'''# Exemple de code pour le chiffre de César
def caesar_cipher(text, shift, mode='encrypt'):
    result = ''
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shift_val = shift if mode=='encrypt' else -shift
            result += chr((ord(char) - base + shift_val) % 26 + base)
        else:
            result += char
    return result
''', language='python')
    st.write("Le code complet de la cryptographie moderne est également intégré dans l’application.")

###########################################
# 5. Comparaison des Algorithmes           #
###########################################
elif section == "Comparaison des Algorithmes":
    st.title("Comparaison des Algorithmes")
    st.markdown("""
    **Explications détaillées :**
    
    Dans cette section, nous comparons le temps d’exécution de deux algorithmes de chiffrement symétrique (AES et RC4)
    en effectuant 1000 itérations sur un même texte. Le but est d’illustrer la différence de performance.
    """)
    text = st.text_area("Entrez un texte pour le benchmark", value="Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
    key = st.text_input("Clé")
    if st.button("Lancer Benchmark AES vs RC4"):
        # Mesure du temps pour AES
        start = time.time()
        for _ in range(1000):
            aes_encrypt(text, key)
        aes_time = time.time() - start

        # Mesure du temps pour RC4
        start = time.time()
        for _ in range(1000):
            rc4_encrypt(text, key)
        rc4_time = time.time() - start

        st.write(f"Temps AES : {aes_time:.4f} secondes")
        st.write(f"Temps RC4 : {rc4_time:.4f} secondes")

        # Visualisation via un diagramme en barres
        algorithms = ['AES', 'RC4']
        times = [aes_time, rc4_time]
        fig, ax = plt.subplots()
        ax.bar(algorithms, times)
        ax.set_ylabel('Temps (secondes)')
        ax.set_title('Benchmark des Algorithmes')
        st.pyplot(fig)

###########################################
# 6. Applications Pratiques                #
###########################################
elif section == "Applications Pratiques":
    st.title("Applications Pratiques")
    st.markdown("""
    **Explications détaillées :**
    
    - **Stockage sécurisé de mots de passe** : Utilise un hachage avec un sel aléatoire pour sécuriser le mot de passe.
    - **Chiffrement de fichiers** : Démonstration de chiffrement de fichier en utilisant AES.
    - **Échange de clés sécurisé** : Exemple illustratif basé sur Diffie-Hellman.
    - **Signature numérique** : Permet de signer un message avec RSA et de vérifier la signature.
    """)
    app_choice = st.radio(
        "Choisissez l'application",
        ("Stockage sécurisé de mots de passe", "Chiffrement de fichiers", "Échange de clés sécurisé", "Signature numérique")
    )
    if app_choice == "Stockage sécurisé de mots de passe":
        st.subheader("Stockage sécurisé de mots de passe")
        st.info("""
        **Comment ça marche ?**
        - Le mot de passe est combiné avec un sel aléatoire.
        - La fonction PBKDF2_HMAC (avec SHA-256) est appliquée pour générer un hachage sécurisé.
        - Le résultat est une chaîne contenant le sel et le hachage, séparés par ':'.
        """)
        password = st.text_input("Entrez le mot de passe", type="password")
        if st.button("Hasher"):
            hashed = hash_password(password)
            st.write("Mot de passe haché (avec sel) :", hashed)
    elif app_choice == "Chiffrement de fichiers":
        st.subheader("Chiffrement de fichiers")
        st.info("""
        **Comment ça marche ?**
        - Le fichier sélectionné est lu et converti en texte.
        - AES est utilisé pour chiffrer le contenu en utilisant une clé donnée.
        - Le résultat chiffré est affiché.
        """)
        uploaded_file = st.file_uploader("Choisissez un fichier", type=["txt", "pdf", "docx"])
        key = st.text_input("Clé pour AES")
        if st.button("Chiffrer le fichier"):
            if uploaded_file:
                file_bytes = uploaded_file.read()
                try:
                    # Pour la démo, on considère que le fichier est du texte
                    content = file_bytes.decode('utf-8')
                    encrypted = aes_encrypt(content, key)
                    st.write("Contenu chiffré :", encrypted)
                except Exception as e:
                    st.error("Erreur lors du chiffrement du fichier : " + str(e))
    elif app_choice == "Échange de clés sécurisé":
        st.subheader("Échange de clés sécurisé")
        st.info("Pour l'échange de clés sécurisé, consultez la section Diffie-Hellman dans 'Cryptographie Moderne'.")
    elif app_choice == "Signature numérique":
        st.subheader("Signature numérique")
        st.info("""
        **Comment ça marche ?**
        - Le message est signé en utilisant une clé privée avec RSA.
        - La signature permet ensuite de vérifier l'authenticité du message avec la clé publique correspondante.
        """)
        message = st.text_area("Entrez le message")
        private_key_input = st.text_area("Entrez la clé privée pour signer", height=150)
        if st.button("Signer"):
            signature = rsa_sign(message, private_key_input)
            st.write("Signature :", signature)
        public_key_input = st.text_area("Entrez la clé publique pour vérifier", height=150)
        signature_input = st.text_input("Entrez la signature")
        if st.button("Vérifier"):
            valid = rsa_verify(message, signature_input, public_key_input)
            if valid:
                st.success("La signature est valide")
            else:
                st.error("Signature invalide")
