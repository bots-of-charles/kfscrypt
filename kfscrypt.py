#!/usr/bin/python3.9

# This program is based on the following tutorial:
# https://www.geeksforgeeks.org/encrypt-and-decrypt-files-using-python/

from cryptography.fernet import Fernet
from pathlib import Path
from sys import argv

_app_dir=argv[0]
_app_args=argv[1:]

_app_name=Path(_app_dir).name
_app_stem=Path(_app_dir).stem
_key_name=_app_stem+".fernet.key"

_megabyte=1048576
_megabyte_enc=1398200

_arg_key_create="kc"
_arg_key_display="kd"
_arg_encrypt="en"
_arg_decrypt="de"

_sfx_enc="."+_arg_encrypt
_sfx_dec="."+_arg_decrypt

_msg_usage=f"""
User guide for {_app_name}
(Last edit: 2023-01-13)

This program encrypts or decrypts files under the Fernet specification
More info here → https://github.com/fernet/spec/blob/master/Spec.md")

Usage:
$ {_app_name} [Action] [Path or filename]

Actions:
{_arg_key_create} → Create a new key
{_arg_key_display} → Display a key
{_arg_encrypt} → Encrypt one or more files
{_arg_decrypt} → Decrypt one or more files

Important to know:
→ The current working directory (CWD) is where a key is read or created
→ Key related actions ("{_arg_key_create}" and "{_arg_key_display}") do not require the path argument
→ When creating or reading a key, this key is named "{_key_name}"
→ All files that were encrypted with a key must be decrypted with that exact same key
→ When using a path, if the path leads to a directory, all the files inside the directory are processed (non-recursively)
→ When encrypting, the output directory is called "{_app_stem+_sfx_enc}" relative to the CWD
→ When decrypting, the output directory is called "{_app_stem+_sfx_dec}" relative to the CWD
"""

_msg_err_args1="Exceeded the number of args"
_msg_err_args2="Unknown action"
_msg_err_args3="Key related actions do not require the path argument"
_msg_err_key1=f"The key \"{_key_name}\" does not exists here"
_msg_err_key2=f"The key \"{_key_name}\" already exists here"
_msg_err_key3="While creating the key"
_msg_err_key4="While reading the key"
_msg_err_path1="The given path does not exist"
_msg_err_path2="There are no files in the given path"
_msg_err_skip="Skipping this file"

def key_read(just_show=True):
	k=open(_key_name).read()
	if just_show:
		return k

	try:
		fkey=Fernet(k)
	except:
		return None

	return fkey

def get_files(given_path):
	ls_files=[]
	ls_files_raw=[]

	if given_path.is_file():
		ls_files_raw.append(given_path)

	if given_path.is_dir():
		for fse in list(given_path.glob("*")):
			if fse.is_file():
				ls_files_raw.append(fse)

	for fse in ls_files_raw:
		illegal=(fse.name.lower() in [_key_name.lower(),_app_name.lower()])
		if not illegal:
			ls_files.append(fse)

	return ls_files

def convert(ipath,opath,the_key,jobtype):
	if jobtype==_arg_encrypt:
		cs=_megabyte
	if jobtype==_arg_decrypt:
		cs=_megabyte_enc

	try:

		if opath.exists():
			raise Exception(_msg_err_skip)

		with open(str(ipath),"rb") as ifile:
			while True:
				chunk=ifile.read(cs)
				if not chunk:
					break

				if chunk:
					if jobtype==_arg_encrypt:
						data=the_key.encrypt(chunk)
					if jobtype==_arg_decrypt:
						data=the_key.decrypt(chunk)

					omode="wb"
					if opath.exists():
						omode="ab"

					with open(str(opath),omode) as ofile:
						ofile.write(data)

	except Exception as e:
		print("\t→",e)
		return False

	return True

def main(args):

	if len(args)==0:

		print(80*"-")
		print(_msg_usage)
		print(80*"-")

	if len(args)>0:

		action=args[0]

		if len(args)>2:
			print("Error:",_msg_err_args)
			return

		if not (action in [_arg_key_create,_arg_key_display,_arg_encrypt,_arg_decrypt]):
			print(f"Error\n{_msg_err_args2}:",action)
			return

		keyman=(action in [_arg_key_create,_arg_key_display])
		if keyman and len(args)==2:
			print("Error:",_msg_err_args3)
			return

		key_exists=Path(_key_name).exists()

		if keyman:
			if action==_arg_key_display:
				if not key_exists:
					print("Error:",_msg_err_key1)
					return

				print(key_read())

			if action==_arg_key_create:
				if key_exists:
					print("Error:",_msg_err_key2)
					return

				try:
					key=Fernet.generate_key()
					open(_key_name,"wb").write(key)
				except Exception as e:
					print(f"Error\n{_msg_err_key3}:",e)
				else:
					print("OK")

		if (action in [_arg_encrypt,_arg_decrypt]):

			the_path=Path("./")
			if len(args)==2:
				the_path=Path(args[1])

			if not key_exists:
				print("Error:",_msg_err_key1)
				return

			if not the_path.exists():
				print("Error:",_msg_err_path1)
				return

			the_list=get_files(the_path)
			if len(the_list)==0:
				print("Error:",_msg_err_path2)
				return

			try:
				fkey=key_read(False)
			except Exception as e:
				print(f"Error\n{_msg_err_key4}:",e)
				return

			outdir_name=_app_stem
			if action==_arg_encrypt:
				print("\nEncrypting\n")
				outdir_name=outdir_name+_sfx_enc
			if action==_arg_decrypt:
				print("\nDecrypting\n")
				outdir_name=outdir_name+_sfx_dec
			outdir=Path(outdir_name)
			outdir.mkdir(parents=True,exist_ok=True)

			ok=0
			for fse in the_list:
				fse_name=fse.name
				fse_out=outdir.joinpath(fse.name)
				print(fse.name)
				result=convert(fse,fse_out,fkey,action)
				if result:
					print("\t→",fse_out)
					ok=ok+1

			print("\nOK:",ok,"/",len(the_list))

main(_app_args)
