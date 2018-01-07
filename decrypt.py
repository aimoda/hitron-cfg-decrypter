#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri

from pyDes import *
import argparse
import os

def main():
	parser = argparse.ArgumentParser(description="Hitron CFG Decrypter")
	parser.add_argument('-V', '--version', action="version", version="%(prog)s 1.0.0")
	parser.add_argument("-i", action="store", dest="input_filename", required=True, help="input filename")
	parser.add_argument("-o", action="store", dest="output_filename", help="output filename")
	parser.add_argument("-m", action="store", dest="mode", default="decrypt", help="decrypt (default) or encrypt")

	args = parser.parse_args()

	output_filename = args.output_filename
	if output_filename is None:
		output_filename = args.input_filename + ".out"

	mode = args.mode
	if mode != "decrypt" and mode != "encrypt":
		raise ValueError("Cannot decrypt and encrypt at the same time.")

	input_filename = args.input_filename

	file_handle = open(input_filename, "rb")

	# Source: https://github.com/habohitron/habohitron/blob/6add0d002fe553f0924a3bba197994c53ca7d52d/firmwares/3.1.1.21/analyse/hc.c#L17
	key = des(b"W\x8a\x95\x8e=\xd93\xfc", ECB, pad=" ", padmode=PAD_NORMAL)

	output = None

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	if mode == "decrypt":
		output = key.decrypt(file_handle.read())
		print("Successfully decrypted!");
	elif mode == "encrypt":
		output = key.encrypt(file_handle.read())
		print("Successfully encrypted.")

	file_handle.close()

	file_handle = open(output_filename, "wb")
	file_handle.write(output)
	file_handle.close()

	print("Output written to: " + output_filename)

if __name__ == '__main__':
	main()
