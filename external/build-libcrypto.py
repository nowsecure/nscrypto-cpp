#!/bin/python

import hashlib
from multiprocessing import cpu_count
import os
import os.path
import shutil
import subprocess
import urllib2

OPENSSL_VERSION = "1.0.2a"

if cpu_count() > 2:
	MAKE_OPT = "-j%d" % (cpu_count() / 2)
else:
	MAKE_OPT = ""

ARCHS = [
	("i386",   "iphonesimulator", "darwin-i386-cc"),
	("x86_64", "iphonesimulator", "darwin64-x86_64-cc"),
	("armv7",  "iphoneos", "iphoneos-cross"),
	("armv7s", "iphoneos", "iphoneos-cross"),
	("arm64",  "iphoneos", "iphoneos-cross"),
]

CONFIGS = [
	("O0", "-O0"),
	("O3", "-O3"),
]

OPTIONS = "no-shared"

def get_openssl_sha1(version):
	url = "https://www.openssl.org/source/openssl-%s.tar.gz.sha1" % version
	return urllib2.urlopen(url).read().strip().lower()


def download_openssl(version):
	url = "https://www.openssl.org/source/openssl-%s.tar.gz" % version
	if subprocess.call(["curl", "-O", url]):
		raise RuntimeError("Cannot download OpenSSL")
	return os.path.basename(url)


def get_file_sha1(name):
	if os.path.isfile(name):
		with open(name, "rb") as f:
			return hashlib.sha1(f.read()).hexdigest().lower()


def download_openssl_if_needed(version):
	name = "openssl-%s.tar.gz" % version
	sha1 = get_file_sha1(name)
	if sha1 and sha1 == get_openssl_sha1(version):
		print "%s is already downloaded" % name
		return name
	else:
		return download_openssl(version)


def untar_file(path, outdir):
	if subprocess.call(["tar", "-xzf", path, "-C", outdir]):
		raise RuntimeError("Cannot untar OpenSSL")


def build(arch, platform, target, oflag, src_dir, build_dir):
	print ""
	print "===== Building for %s using %s (%s) =====" % (arch, platform, oflag)
	subprocess.call(["sed", "-ie", "s!static volatile sig_atomic_t intr_signal;!static volatile intr_signal;!",
					 os.path.join(src_dir, "crypto/ui/ui_openssl.c")])
	gcc = subprocess.check_output(["xcrun", "--sdk", platform, "--find", "gcc"]).strip()
	cc = "%s -arch %s -miphoneos-version-min=5.0" % (gcc, arch)
	makedep = "%s -M" % cc

	# $(CROSS_TOP)/SDKs/\$(CROSS_SDK)
	cross_top = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-platform-path"]).strip()
	cross_top = os.path.join(cross_top, "Developer")

	sysroot = subprocess.check_output(["xcrun", "--sdk", platform, "--show-sdk-path"]).strip()
	cross_sdk = os.path.basename(sysroot)

	with open(os.path.join(build_dir, "openssl-build.log"), "w") as log:
		config_cmd = "./Configure %s %s --openssldir=\"%s\"" % (target, OPTIONS, os.path.abspath(build_dir))
		print config_cmd

		if subprocess.call(config_cmd, shell=True, stdout=log, stderr=log, cwd=src_dir, env={"CC": cc}):
			print "There was a problem while configuring OpenSSL -- see log"
			return False

		# Set desired -O level (and sysroot)
		if platform == "iphonesimulator":
			cflag = "%s -isysroot %s" % (oflag, sysroot)
			subprocess.call(["sed",  "-ie", "s![[:space:]]-O3[[:space:]]! %s !" % cflag, os.path.join(src_dir, "Makefile")])
		else:
			subprocess.call(["sed",  "-ie", "s![[:space:]]-O3[[:space:]]! %s !" % oflag, os.path.join(src_dir, "Makefile")])
		subprocess.call(["sed", "-ie", "s!MAKEDEPPROG=makedepend!MAKEDEPPROG=%s!" % makedep, os.path.join(src_dir, "Makefile")])

		cross_env = {
			"CROSS_TOP": cross_top,
			"CROSS_SDK": cross_sdk,
		}

		'''
		make_cmd = "make depend"
		print make_cmd
		if subprocess.call(make_cmd, shell=True, stdout=log, stderr=log, cwd=src_dir, env=cross_env):
			print "There was a problem while 'make depend' -- see log"
			return False
		'''

		make_cmd = "make build_crypto %s" % MAKE_OPT
		print make_cmd
		if subprocess.call(make_cmd, shell=True, stdout=log, stderr=log, cwd=src_dir, env=cross_env):
			print "There was a problem while 'make build_crypto' -- see log"
			return False

		src = os.path.join(src_dir, "libcrypto.a")
		lib = os.path.join(build_dir, "libcrypto.a")
		shutil.move(src, lib)

		src = os.path.join(src_dir, "include", "openssl")
		dst = os.path.join("include", arch, "openssl")
		shutil.rmtree(dst, True)
		shutil.copytree(src, dst)

	return lib


def main():
	print "Downloading and building libcrypto-%s" % OPENSSL_VERSION
	name = download_openssl_if_needed(OPENSSL_VERSION)
	sha1 = get_file_sha1(name)
	print "SHA1(%s) = %s" % (name, sha1)

	try: os.makedirs("src")
	except: pass
	try: os.makedirs("include")
	except: pass
	try: os.makedirs("build")
	except: pass

	src_dir = os.path.join("src", name[0:name.index(".tar.gz")])
	build_root = "build"

	for config_name, oflag in CONFIGS:
		thin_libs = []
		for arch, platform, target in ARCHS:
			shutil.rmtree(src_dir, True)
			untar_file(name, "src")

			build_dir = os.path.join("build", arch)
			shutil.rmtree(build_dir, True)
			
			try:
				os.makedirs(build_dir)
			except:
				pass
			lib = build(arch, platform, target, oflag, src_dir, build_dir)
			if not lib:
				return

			thin_libs.append(lib)

		print "Combining built libraries"
		lib_name = "libcrypto_%s.a" % config_name
		if subprocess.call(["lipo", "-create"] + thin_libs + ["-output", lib_name]):
			print "There was a problem lipo'ing libraries"
			return

		print "Built library is saved as", lib_name

	shutil.rmtree("src", True)
	shutil.rmtree("build", True)


if __name__ == "__main__":
	main()
	print ""
	print "Goodbye."
