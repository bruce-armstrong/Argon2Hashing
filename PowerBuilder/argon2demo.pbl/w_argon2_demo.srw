//objectcomments Demo: hash and verify passwords with Argon2 through the imported .NET proxy nvo_argon2hasher
forward
global type w_argon2_demo from window
end type
type gb_settings from groupbox within w_argon2_demo
end type
type st_variant from statictext within w_argon2_demo
end type
type ddlb_variant from dropdownlistbox within w_argon2_demo
end type
type st_memory from statictext within w_argon2_demo
end type
type sle_memory from singlelineedit within w_argon2_demo
end type
type st_iterations from statictext within w_argon2_demo
end type
type sle_iterations from singlelineedit within w_argon2_demo
end type
type st_parallelism from statictext within w_argon2_demo
end type
type sle_parallelism from singlelineedit within w_argon2_demo
end type
type st_pepper from statictext within w_argon2_demo
end type
type sle_pepper from singlelineedit within w_argon2_demo
end type
type cb_apply from commandbutton within w_argon2_demo
end type
type st_password from statictext within w_argon2_demo
end type
type sle_password from singlelineedit within w_argon2_demo
end type
type cb_hash from commandbutton within w_argon2_demo
end type
type st_hash from statictext within w_argon2_demo
end type
type sle_hash from singlelineedit within w_argon2_demo
end type
type st_verify from statictext within w_argon2_demo
end type
type sle_verify from singlelineedit within w_argon2_demo
end type
type cb_verify from commandbutton within w_argon2_demo
end type
type cb_rehash from commandbutton within w_argon2_demo
end type
type st_result from statictext within w_argon2_demo
end type
type mle_log from multilineedit within w_argon2_demo
end type
end forward

global type w_argon2_demo from window
integer width = 3264
integer height = 2200
boolean titlebar = true
string title = "Argon2 Password Hashing Demo (.NET assembly import)"
boolean controlmenu = true
boolean minbox = true
boolean maxbox = true
boolean resizable = true
long backcolor = 67108864
string icon = "AppIcon!"
boolean center = true
event ue_argon2_error ( )
gb_settings gb_settings
st_variant st_variant
ddlb_variant ddlb_variant
st_memory st_memory
sle_memory sle_memory
st_iterations st_iterations
sle_iterations sle_iterations
st_parallelism st_parallelism
sle_parallelism sle_parallelism
st_pepper st_pepper
sle_pepper sle_pepper
cb_apply cb_apply
st_password st_password
sle_password sle_password
cb_hash cb_hash
st_hash st_hash
sle_hash sle_hash
st_verify st_verify
sle_verify sle_verify
cb_verify cb_verify
cb_rehash cb_rehash
st_result st_result
mle_log mle_log
end type
global w_argon2_demo w_argon2_demo

type variables
nvo_argon2hasher	inv_argon2
end variables

forward prototypes
public subroutine wf_log (string as_msg)
public subroutine wf_result (boolean ab_ok, string as_msg)
public subroutine wf_load_settings ()
end prototypes

event ue_argon2_error();// Raised by nvo_argon2hasher (of_SetErrorHandler) when the assembly cannot be loaded or a .NET call throws.
wf_result(false, ".NET error: " + inv_argon2.is_errortext)
end event

public subroutine wf_log (string as_msg);mle_log.text += String(Now(), "hh:mm:ss") + "   " + as_msg + "~r~n"
mle_log.Scroll(mle_log.LineCount())
end subroutine

public subroutine wf_result (boolean ab_ok, string as_msg);if ab_ok then
	st_result.textcolor = RGB(0, 128, 0)
else
	st_result.textcolor = RGB(192, 0, 0)
end if
st_result.text = as_msg
wf_log(as_msg)
end subroutine

public subroutine wf_load_settings ();// Show the hasher's current settings in the settings fields.
ddlb_variant.SelectItem(inv_argon2.of_getvariant(), 0)
sle_memory.text = String(inv_argon2.of_getmemorykib())
sle_iterations.text = String(inv_argon2.of_getiterations())
sle_parallelism.text = String(inv_argon2.of_getparallelism())
end subroutine

on w_argon2_demo.create
this.gb_settings=create gb_settings
this.st_variant=create st_variant
this.ddlb_variant=create ddlb_variant
this.st_memory=create st_memory
this.sle_memory=create sle_memory
this.st_iterations=create st_iterations
this.sle_iterations=create sle_iterations
this.st_parallelism=create st_parallelism
this.sle_parallelism=create sle_parallelism
this.st_pepper=create st_pepper
this.sle_pepper=create sle_pepper
this.cb_apply=create cb_apply
this.st_password=create st_password
this.sle_password=create sle_password
this.cb_hash=create cb_hash
this.st_hash=create st_hash
this.sle_hash=create sle_hash
this.st_verify=create st_verify
this.sle_verify=create sle_verify
this.cb_verify=create cb_verify
this.cb_rehash=create cb_rehash
this.st_result=create st_result
this.mle_log=create mle_log
this.Control[]={this.gb_settings,&
this.st_variant,&
this.ddlb_variant,&
this.st_memory,&
this.sle_memory,&
this.st_iterations,&
this.sle_iterations,&
this.st_parallelism,&
this.sle_parallelism,&
this.st_pepper,&
this.sle_pepper,&
this.cb_apply,&
this.st_password,&
this.sle_password,&
this.cb_hash,&
this.st_hash,&
this.sle_hash,&
this.st_verify,&
this.sle_verify,&
this.cb_verify,&
this.cb_rehash,&
this.st_result,&
this.mle_log}
end on

on w_argon2_demo.destroy
destroy(this.gb_settings)
destroy(this.st_variant)
destroy(this.ddlb_variant)
destroy(this.st_memory)
destroy(this.sle_memory)
destroy(this.st_iterations)
destroy(this.sle_iterations)
destroy(this.st_parallelism)
destroy(this.sle_parallelism)
destroy(this.st_pepper)
destroy(this.sle_pepper)
destroy(this.cb_apply)
destroy(this.st_password)
destroy(this.sle_password)
destroy(this.cb_hash)
destroy(this.st_hash)
destroy(this.sle_hash)
destroy(this.st_verify)
destroy(this.sle_verify)
destroy(this.cb_verify)
destroy(this.cb_rehash)
destroy(this.st_result)
destroy(this.mle_log)
end on

event open;string ls_version

inv_argon2 = create nvo_argon2hasher
// Route load/call failures of the proxy to this window's ue_argon2_error event.
inv_argon2.of_seterrorhandler(this, "ue_argon2_error")

// The first call loads Argon2Hashing.dll and creates the .NET object.
ls_version = inv_argon2.of_getlibraryversion()
if IsNull(ls_version) then
	MessageBox("Argon2 Demo", "Could not load the .NET assembly:~r~n~r~n" + inv_argon2.is_errortext + &
		"~r~n~r~nArgon2Hashing.dll must be next to the exe (or in the solution folder when running from the IDE), " + &
		"and the .NET 8 Desktop Runtime matching this app's bitness must be installed.", StopSign!)
	cb_apply.enabled = false
	cb_hash.enabled = false
	cb_verify.enabled = false
	cb_rehash.enabled = false
	return
end if

wf_load_settings()
wf_log("Loaded Argon2Hashing.dll " + ls_version + " - defaults: " + inv_argon2.of_getvariant() + &
	", m=" + String(inv_argon2.of_getmemorykib()) + " KiB, t=" + String(inv_argon2.of_getiterations()) + &
	", p=" + String(inv_argon2.of_getparallelism()))
wf_log("1) type a password and click Hash   2) type a password to check and click Verify")
end event

event close;if IsValid(inv_argon2) then destroy inv_argon2
end event

event resize;sle_hash.width = newwidth - sle_hash.x - 40
st_result.width = newwidth - st_result.x - 40
mle_log.width = newwidth - mle_log.x - 40
mle_log.height = newheight - mle_log.y - 40
gb_settings.width = newwidth - gb_settings.x - 40
end event

type gb_settings from groupbox within w_argon2_demo
integer x = 37
integer y = 20
integer width = 3150
integer height = 360
integer taborder = 10
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Settings (used for new hashes; Verify reads the settings stored in the hash)"
end type

type st_variant from statictext within w_argon2_demo
integer x = 91
integer y = 124
integer width = 247
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Variant:"
boolean focusrectangle = false
end type

type ddlb_variant from dropdownlistbox within w_argon2_demo
integer x = 347
integer y = 108
integer width = 434
integer height = 400
integer taborder = 20
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
boolean sorted = false
string item[] = {"argon2id","argon2i","argon2d"}
borderstyle borderstyle = stylelowered!
end type

type st_memory from statictext within w_argon2_demo
integer x = 837
integer y = 124
integer width = 393
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Memory (KiB):"
boolean focusrectangle = false
end type

type sle_memory from singlelineedit within w_argon2_demo
integer x = 1239
integer y = 108
integer width = 315
integer height = 88
integer taborder = 30
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
borderstyle borderstyle = stylelowered!
end type

type st_iterations from statictext within w_argon2_demo
integer x = 1609
integer y = 124
integer width = 297
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Iterations:"
boolean focusrectangle = false
end type

type sle_iterations from singlelineedit within w_argon2_demo
integer x = 1915
integer y = 108
integer width = 183
integer height = 88
integer taborder = 40
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
borderstyle borderstyle = stylelowered!
end type

type st_parallelism from statictext within w_argon2_demo
integer x = 2153
integer y = 124
integer width = 325
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Parallelism:"
boolean focusrectangle = false
end type

type sle_parallelism from singlelineedit within w_argon2_demo
integer x = 2487
integer y = 108
integer width = 183
integer height = 88
integer taborder = 50
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
borderstyle borderstyle = stylelowered!
end type

type st_pepper from statictext within w_argon2_demo
integer x = 91
integer y = 252
integer width = 517
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Pepper (optional):"
boolean focusrectangle = false
end type

type sle_pepper from singlelineedit within w_argon2_demo
integer x = 617
integer y = 236
integer width = 1481
integer height = 88
integer taborder = 60
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
boolean password = true
borderstyle borderstyle = stylelowered!
end type

type cb_apply from commandbutton within w_argon2_demo
integer x = 2153
integer y = 228
integer width = 517
integer height = 104
integer taborder = 70
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
string text = "&Apply settings"
end type

event clicked;// Each setter validates its input and returns false with a reason in GetLastError().
string ls_pepper

if not inv_argon2.of_setvariant(ddlb_variant.text) then
	wf_result(false, "Variant rejected: " + inv_argon2.of_getlasterror())
	wf_load_settings()
	return
end if

if not inv_argon2.of_setparameters(Long(sle_memory.text), Long(sle_iterations.text), Long(sle_parallelism.text)) then
	wf_result(false, "Parameters rejected: " + inv_argon2.of_getlasterror())
	wf_load_settings()
	return
end if

// The pepper is NOT stored in the hash: the same value must be set again before verifying.
inv_argon2.of_setsecret(sle_pepper.text)
if Len(sle_pepper.text) > 0 then ls_pepper = "set" else ls_pepper = "off"

wf_result(true, "Settings applied: " + inv_argon2.of_getvariant() + ", m=" + String(inv_argon2.of_getmemorykib()) + &
	" KiB, t=" + String(inv_argon2.of_getiterations()) + ", p=" + String(inv_argon2.of_getparallelism()) + &
	", pepper " + ls_pepper)
end event

type st_password from statictext within w_argon2_demo
integer x = 37
integer y = 432
integer width = 562
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "New password:"
boolean focusrectangle = false
end type

type sle_password from singlelineedit within w_argon2_demo
integer x = 617
integer y = 416
integer width = 1481
integer height = 88
integer taborder = 80
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
boolean password = true
borderstyle borderstyle = stylelowered!
end type

type cb_hash from commandbutton within w_argon2_demo
integer x = 2153
integer y = 408
integer width = 517
integer height = 104
integer taborder = 90
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
string text = "&Hash"
boolean default = true
end type

event clicked;// Hash with a fresh random salt. The returned PHC string holds variant, parameters, salt and hash:
// store it as-is in a varchar column (about 100 characters with the defaults).
string ls_hash
long ll_start

SetPointer(HourGlass!)
ll_start = Cpu()
ls_hash = inv_argon2.of_hashpassword(sle_password.text)
if IsNull(ls_hash) then return		// proxy error, already reported by ue_argon2_error

if ls_hash = "" then
	wf_result(false, "Hash failed: " + inv_argon2.of_getlasterror())
	return
end if

sle_hash.text = ls_hash
wf_result(true, "Hashed in " + String(Cpu() - ll_start) + " ms: " + ls_hash)
end event

type st_hash from statictext within w_argon2_demo
integer x = 37
integer y = 556
integer width = 562
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Stored hash (PHC):"
boolean focusrectangle = false
end type

type sle_hash from singlelineedit within w_argon2_demo
integer x = 617
integer y = 540
integer width = 2569
integer height = 88
integer taborder = 100
integer textsize = -9
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = fixed!
fontfamily fontfamily = modern!
string facename = "Consolas"
long textcolor = 33554432
borderstyle borderstyle = stylelowered!
end type

type st_verify from statictext within w_argon2_demo
integer x = 37
integer y = 680
integer width = 562
integer height = 64
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
string text = "Password to verify:"
boolean focusrectangle = false
end type

type sle_verify from singlelineedit within w_argon2_demo
integer x = 617
integer y = 664
integer width = 1481
integer height = 88
integer taborder = 110
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
boolean password = true
borderstyle borderstyle = stylelowered!
end type

type cb_verify from commandbutton within w_argon2_demo
integer x = 2153
integer y = 656
integer width = 517
integer height = 104
integer taborder = 120
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
string text = "&Verify"
end type

event clicked;// Verify re-hashes the candidate with the salt and parameters stored in the hash string,
// then compares in constant time.
boolean lb_match
string ls_error
long ll_start

SetPointer(HourGlass!)
ll_start = Cpu()
lb_match = inv_argon2.of_verifypassword(sle_verify.text, sle_hash.text)
if IsNull(lb_match) then return		// proxy error, already reported by ue_argon2_error

if lb_match then
	wf_result(true, "Password MATCHES (" + String(Cpu() - ll_start) + " ms)")
	// Typical login flow: after a successful verify, upgrade old hashes to the current settings.
	if inv_argon2.of_needsrehash(sle_hash.text) then
		wf_log("   This hash uses older settings - a real app would now store of_HashPassword(password).")
	end if
else
	ls_error = inv_argon2.of_getlasterror()
	if ls_error = "" then
		wf_result(false, "Password does NOT match")
	else
		wf_result(false, "Invalid hash: " + ls_error)
	end if
end if
end event

type cb_rehash from commandbutton within w_argon2_demo
integer x = 2688
integer y = 656
integer width = 498
integer height = 104
integer taborder = 130
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
string text = "Needs re&hash?"
end type

event clicked;if not inv_argon2.of_isvalidhash(sle_hash.text) then
	wf_result(false, "Not a valid Argon2 hash: " + inv_argon2.of_getlasterror())
elseif inv_argon2.of_needsrehash(sle_hash.text) then
	wf_result(false, "Yes - the stored hash differs from the current settings")
else
	wf_result(true, "No - the stored hash matches the current settings")
end if
end event

type st_result from statictext within w_argon2_demo
integer x = 37
integer y = 800
integer width = 3150
integer height = 80
integer textsize = -11
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Tahoma"
long textcolor = 33554432
long backcolor = 67108864
boolean focusrectangle = false
end type

type mle_log from multilineedit within w_argon2_demo
integer x = 37
integer y = 900
integer width = 3150
integer height = 1180
integer taborder = 140
integer textsize = -9
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = fixed!
fontfamily fontfamily = modern!
string facename = "Consolas"
long textcolor = 33554432
boolean vscrollbar = true
boolean autovscroll = true
boolean displayonly = true
borderstyle borderstyle = stylelowered!
end type
