//objectcomments Argon2 password hashing demo. Opens w_argon2_demo, or runs a headless self-test with /selftest.
forward
global transaction sqlca
global dynamicdescriptionarea sqlda
global dynamicstagingarea sqlsa
global error error
global message message
end forward

global type argon2demo from application
 string appruntimeversion = "25.1.0.6430"
integer highdpimode = 0
end type
global argon2demo argon2demo

on argon2demo.create
appname = "argon2demo"
message = create message
sqlca = create transaction
sqlda = create dynamicdescriptionarea
sqlsa = create dynamicstagingarea
error = create error
end on

on argon2demo.destroy
destroy( sqlca )
destroy( sqlda )
destroy( sqlsa )
destroy( error )
destroy( message )
end on

event open;// "argon2demo.exe /selftest" exercises the .NET assembly without a UI and writes
// argon2demo_selftest.txt to the current directory (used by build.ps1 -Test).
n_cst_selftest lnv_test

if Pos(Lower(CommandParm()), "/selftest") > 0 then
	lnv_test = create n_cst_selftest
	lnv_test.of_run("argon2demo_selftest.txt")
	destroy lnv_test
	return
end if

Open(w_argon2_demo)
end event
