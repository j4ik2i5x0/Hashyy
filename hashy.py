#!/usr/bin/python

import click
import hashlib
import bcrypt
import argon2
import crc32c


@click.command()
@click.option('-d', '--data', prompt='Enter data to hash', help='Data to be hashed')
@click.option('-a', '--algorithm', prompt='Choose algorithm (md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, ripemd160, bcrypt, argon2, crc32)', help='Hash algorithm')
def hash_data(data, algorithm):
    if algorithm == 'md5':
        click.echo("MD5: " + md5_hash(data))
    elif algorithm == 'sha1':
        click.echo("SHA-1: " + sha1_hash(data))
    elif algorithm == 'sha224':
        click.echo("SHA-224: " + sha224_hash(data))
    elif algorithm == 'sha256':
        click.echo("SHA-256: " + sha256_hash(data))
    elif algorithm == 'sha384':
        click.echo("SHA-384: " + sha384_hash(data))
    elif algorithm == 'sha512':
        click.echo("SHA-512: " + sha512_hash(data))
    elif algorithm == 'blake2b':
        click.echo("Blake2b: " + blake2b_hash(data))
    elif algorithm == 'blake2s':
        click.echo("Blake2s: " + blake2s_hash(data))
    elif algorithm == 'ripemd160':
        click.echo("RIPEMD-160: " + ripemd160_hash(data))
    elif algorithm == 'bcrypt':
        click.echo("Bcrypt: " + bcrypt_hash(data))
    elif algorithm == 'argon2':
        click.echo("Argon2: " + argon2_hash(data))
    elif algorithm == 'crc32':
        click.echo("CRC32: " + crc32_hash(data))
    else:  
        click.echo("Invalid algorithm choice.")

# Hash functions from hashlib
def md5_hash(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

def sha1_hash(data):
    sha1 = hashlib.sha1()
    sha1.update(data.encode('utf-8'))
    return sha1.hexdigest()

def sha224_hash(data):
    sha224 = hashlib.sha224()
    sha224.update(data.encode('utf-8'))
    return sha224.hexdigest()

def sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()

def sha384_hash(data):
    sha384 = hashlib.sha384()
    sha384.update(data.encode('utf-8'))
    return sha384.hexdigest()

def sha512_hash(data):
    sha512 = hashlib.sha512()
    sha512.update(data.encode('utf-8'))
    return sha512.hexdigest()

def blake2b_hash(data):
    blake2b = hashlib.blake2b(data.encode('utf-8'))
    return blake2b.hexdigest()
def blake2s_hash(data):
    blake2s = hashlib.blake2s(data.encode('utf-8'))
    return blake2s.hexdigest()

def ripemd160_hash(data):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(data.encode('utf-8'))
    return ripemd160.hexdigest()

# Hash functions from bcrypt and argon2
def bcrypt_hash(data):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(data.encode('utf-8'), salt)
    return hashed

def argon2_hash(data):
    hasher = argon2.PasswordHasher()
    hashed = hasher.hash(data)
    return hashed

# Other hash functions
def crc32_hash(data):
    return hex(crc32c.crc32c(data.encode('utf-8')))
if __name__ == "__main__":
    click.echo(r"""

 __    __       ___           _______. __    __  ____    ____ 
|  |  |  |     /   \         /       ||  |  |  | \   \  /   / 
|  |__|  |    /  ^  \       |   (----`|  |__|  |  \   \/   /  
|   __   |   /  /_\  \       \   \    |   __   |   \_    _/   
|  |  |  |  /  _____  \  .----)   |   |  |  |  |     |  |     
|__|  |__| /__/     \__\ |_______/    |__|  |__|     |__|     

= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =                                                    


""")
    click.echo("Welcome to the Hashy Tool!")
    click.echo("This tool allows you to perform various hashing operations.")
    click.echo("Usage: hashy [OPTIONS]")
    click.echo("Options:")
    click.echo("  -d, --data     Data to be hashed")
    click.echo("  -a, --algorithm     Hash algorithm to use (md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, ripemd160, bcrypt, argon2, crc32)")
    click.echo("")
    click.echo("Description of hash functions:")
    click.echo("  - md5: MD5 hash function. Produces a 128-bit (16-byte) hash value.")
    click.echo("  - sha1: SHA-1 hash function. Produces a 160-bit (20-byte) hash value.")
    click.echo("  - sha224: SHA-224 hash function. Produces a 224-bit (28-byte) hash value.")
    click.echo("  - sha256: SHA-256 hash function. Produces a 256-bit (32-byte) hash value.")
    click.echo("  - sha384: SHA-384 hash function. Produces a 384-bit (48-byte) hash value.")
    click.echo("  - sha512: SHA-512 hash function. Produces a 512-bit (64-byte) hash value.")
    click.echo("  - blake2b: Blake2b hash function. Produces a variable-length hash value.")
    click.echo("  - blake2s: Blake2s hash function. Produces a variable-length hash value.")
    click.echo("  - ripemd160: RIPEMD-160 hash function. Produces a 160-bit (20-byte) hash value.")
    click.echo("  - bcrypt: Bcrypt hash function. A secure password hashing algorithm.")
    click.echo("  - argon2: Argon2 hash function. Another secure password hashing algorithm.")
    click.echo("  - crc32: CRC32 checksum function. Calculates a 32-bit checksum of the data.")
    click.echo("")
    hash_data()
