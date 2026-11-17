//objectcomments Headless end-to-end check of nvo_argon2hasher -> Argon2Hashing.dll. Writes PASS/FAIL lines to a text file.
forward
global type n_cst_selftest from nonvisualobject
end type
end forward

global type n_cst_selftest from nonvisualobject
end type
global n_cst_selftest n_cst_selftest

type variables
PRIVATE:
	string	is_report
	integer	ii_failures
end variables

forward prototypes
public function integer of_run (string as_reportfile)
private subroutine of_check (string as_name, boolean ab_ok)
private subroutine of_line (string as_text)
end prototypes

public function integer of_run (string as_reportfile);// Returns the number of failed checks (0 = all passed).
nvo_argon2hasher lnv_argon2
string ls_version, ls_hash, ls_known, ls_unicode
integer li_file

// Reference hash from the libargon2 README:
//   echo -n "password" | argon2 somesalt -t 2 -m 16 -p 4 -l 24
ls_known = "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
ls_unicode = "pässwörd-密码"

lnv_argon2 = create nvo_argon2hasher

ls_version = lnv_argon2.of_getlibraryversion()
if IsNull(ls_version) then
	of_check("load Argon2Hashing.dll: " + lnv_argon2.is_errortext, false)
else
	of_line("Argon2Hashing.dll version " + ls_version)
	of_check("assembly loaded", true)

	ls_hash = lnv_argon2.of_hashpassword(ls_unicode)
	of_line("hash: " + ls_hash)
	of_check("default hash is argon2id m=65536,t=3,p=4", Left(ls_hash, 31) = "$argon2id$v=19$m=65536,t=3,p=4$")
	of_check("verify correct password", lnv_argon2.of_verifypassword(ls_unicode, ls_hash))
	of_check("reject wrong password", not lnv_argon2.of_verifypassword("pässwörd-密", ls_hash))
	of_check("verify libargon2 reference hash", lnv_argon2.of_verifypassword("password", ls_known))
	of_check("no rehash with same settings", not lnv_argon2.of_needsrehash(ls_hash))

	of_check("SetParameters(19456, 2, 1)", lnv_argon2.of_setparameters(19456, 2, 1))
	of_check("GetMemoryKiB = 19456", lnv_argon2.of_getmemorykib() = 19456)
	of_check("rehash needed after change", lnv_argon2.of_needsrehash(ls_hash))
	of_check("SetParameters rejects 4 KiB", not lnv_argon2.of_setparameters(4, 1, 1))
	of_check("GetLastError explains rejection", Len(lnv_argon2.of_getlasterror()) > 0)
	of_check("SetVariant rejects bcrypt", not lnv_argon2.of_setvariant("bcrypt"))
	of_check("SetVariant argon2i", lnv_argon2.of_setvariant("argon2i") and lnv_argon2.of_getvariant() = "argon2i")

	lnv_argon2.of_setvariant("argon2id")
	lnv_argon2.of_setsecret("pepper")
	ls_hash = lnv_argon2.of_hashpassword("pw")
	of_check("peppered hash verifies", lnv_argon2.of_verifypassword("pw", ls_hash))
	lnv_argon2.of_setsecret("")
	of_check("peppered hash needs the pepper", not lnv_argon2.of_verifypassword("pw", ls_hash))
	of_check("garbage hash is rejected", not lnv_argon2.of_verifypassword("pw", "not a hash"))
	of_check("no proxy errors", lnv_argon2.il_errortype = lnv_argon2.SUCCESS)
end if

destroy lnv_argon2

if ii_failures = 0 then
	of_line("RESULT: PASS")
else
	of_line("RESULT: FAIL (" + String(ii_failures) + ")")
end if

li_file = FileOpen(as_reportfile, TextMode!, Write!, LockWrite!, Replace!, EncodingUTF8!)
if li_file > 0 then
	FileWriteEx(li_file, is_report)
	FileClose(li_file)
end if

return ii_failures
end function

private subroutine of_check (string as_name, boolean ab_ok);if IsNull(ab_ok) then ab_ok = false
if ab_ok then
	of_line("PASS  " + as_name)
else
	of_line("FAIL  " + as_name)
	ii_failures++
end if
end subroutine

private subroutine of_line (string as_text);is_report += as_text + "~r~n"
end subroutine

on n_cst_selftest.create
call super::create
TriggerEvent( this, "constructor" )
end on

on n_cst_selftest.destroy
TriggerEvent( this, "destructor" )
call super::destroy
end on
