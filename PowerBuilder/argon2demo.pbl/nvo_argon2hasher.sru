//objectcomments .NET proxy for Argon2Hashing.Argon2Hasher (Argon2Hashing.dll), in the shape the .NET DLL Importer generates. Re-import to regenerate.
forward
global type nvo_argon2hasher from dotnetobject
end type
end forward

global type nvo_argon2hasher from dotnetobject
event ue_error ( )
end type
global nvo_argon2hasher nvo_argon2hasher

type variables

PUBLIC:
String is_assemblypath = "Argon2Hashing.dll"
String is_classname = "Argon2Hashing.Argon2Hasher"

/* Exception handling -- Indicates how proxy handles .NET exceptions */
Boolean ib_CrashOnException = False

/*      Error types       */
Constant Int SUCCESS        =  0 // No error since latest reset
Constant Int LOAD_FAILURE   = -1 // Failed to load assembly
Constant Int CREATE_FAILURE = -2 // Failed to create .NET object
Constant Int CALL_FAILURE   = -3 // Call to .NET function failed

/* Latest error -- Public reset via of_ResetError */
PRIVATEWRITE Long il_ErrorType
PRIVATEWRITE Long il_ErrorNumber
PRIVATEWRITE String is_ErrorText

PRIVATE:
/*  .NET object creation */
Boolean ib_objectCreated

/* Error handler -- Public access via of_SetErrorHandler/of_ResetErrorHandler/of_GetErrorHandler
    Triggers "ue_Error" event for each error when no current error handler */
PowerObject ipo_errorHandler // Each error triggers <ErrorHandler, ErrorEvent>
String is_errorEvent
end variables

forward prototypes
public subroutine of_seterrorhandler (powerobject apo_newhandler, string as_newevent)
public subroutine of_signalerror ()
private subroutine of_setdotneterror (string as_failedfunction, string as_errortext)
public subroutine of_reseterror ()
public function boolean of_createondemand ()
private subroutine of_setassemblyerror (long al_errortype, string as_actiontext, long al_errornumber, string as_errortext)
public subroutine of_geterrorhandler (ref powerobject apo_currenthandler, ref string as_currentevent)
public subroutine of_reseterrorhandler ()
public function string of_hashpassword (string as_password)
public function boolean of_verifypassword (string as_password, string as_encodedhash)
public function boolean of_needsrehash (string as_encodedhash)
public function boolean of_isvalidhash (string as_encodedhash)
public function boolean of_setparameters (long al_memorykib, long al_iterations, long al_parallelism)
public function boolean of_setvariant (string as_variant)
public function boolean of_sethashlength (long al_bytes)
public function boolean of_setsaltlength (long al_bytes)
public subroutine of_setsecret (string as_secret)
public function long of_getmemorykib ()
public function long of_getiterations ()
public function long of_getparallelism ()
public function long of_gethashlength ()
public function long of_getsaltlength ()
public function string of_getvariant ()
public function string of_getlasterror ()
public function string of_getlibraryversion ()
end prototypes

event ue_error ( );
/*-----------------------------------------------------------------------------------------*/
/*  Handler undefined or call failed (event undefined) => Signal object itself */
/*-----------------------------------------------------------------------------------------*/
end event

public subroutine of_seterrorhandler (powerobject apo_newhandler, string as_newevent);
//*-----------------------------------------------------------------*/
//*    of_seterrorhandler:
//*                       Register new error handler (incl. event)
//*-----------------------------------------------------------------*/

This.ipo_errorHandler = apo_newHandler
This.is_errorEvent = Trim(as_newEvent)
end subroutine

public subroutine of_signalerror ();
//*-----------------------------------------------------------------------------*/
//* PRIVATE of_SignalError
//* Triggers error event on previously defined error handler.
//* Calls object's own UE_ERROR when handler or its event is undefined.
//*-----------------------------------------------------------------------------*/

Boolean lb_handlerDefined
If This.is_errorEvent > '' Then
	If Not IsNull(This.ipo_errorHandler) Then
		lb_handlerDefined = IsValid(This.ipo_errorHandler)
	End If
End If

If lb_handlerDefined Then
	/* Try to call defined handler*/
	Long ll_status
	ll_status = This.ipo_errorHandler.TriggerEvent(This.is_errorEvent)
	If ll_status = 1 Then Return
End If

/* Handler undefined or call failed (event undefined) => Signal object itself*/
This.event ue_Error( )
end subroutine

private subroutine of_setdotneterror (string as_failedfunction, string as_errortext);
//*----------------------------------------------------------------------------------------*/
//* PRIVATE of_setDotNETError
//* Sets error description for specified error condition exposed by call to .NET
//*----------------------------------------------------------------------------------------*/

String ls_error
ls_error = "Call " + as_failedFunction + " failed."
If Len(Trim(as_errorText)) > 0 Then
	ls_error += "~r~nError Text: " + as_errorText
End If

This.il_ErrorType = This.CALL_FAILURE
This.is_ErrorText = ls_error
This.il_ErrorNumber = 0
end subroutine

public subroutine of_reseterror ();
//*--------------------------------------------*/
//* PUBLIC of_ResetError
//* Clears previously registered error
//*--------------------------------------------*/

This.il_ErrorType = This.SUCCESS
This.is_ErrorText = ''
This.il_ErrorNumber = 0
end subroutine

public function boolean of_createondemand ();
//*--------------------------------------------------------------*/
//*  PUBLIC   of_createOnDemand( )
//*  Return   True:  .NET object created
//*           False: Failed to create .NET object
//*  Loads .NET assembly and creates instance of .NET class.
//*  Uses .NET Core (.NET 8) when loading .NET assembly.
//*  (For the net48 build of the DLL use LoadWithDotNetFramework.)
//*  Signals error If an error occurs.
//*  Resets any prior error when load + create succeeds.
//*--------------------------------------------------------------*/

This.of_ResetError( )
If This.ib_objectCreated Then Return True // Already created => DONE

Long ll_status
String ls_action

/* Load assembly using .NET Core */
ls_action = 'Load ' + This.is_AssemblyPath
DotNetAssembly lnv_assembly
lnv_assembly = Create DotNetAssembly
ll_status = lnv_assembly.LoadWithDotNetCore(This.is_AssemblyPath)

/* Abort when load fails */
If ll_status <> 1 Then
	This.of_SetAssemblyError(This.LOAD_FAILURE, ls_action, ll_status, lnv_assembly.ErrorText)
	This.of_SignalError( )
	Return False // Load failed => ABORT
End If

/*   Create .NET object */
ls_action = 'Create ' + This.is_ClassName
ll_status = lnv_assembly.CreateInstance(is_ClassName, This)

/* Abort when create fails */
If ll_status <> 1 Then
	This.of_SetAssemblyError(This.CREATE_FAILURE, ls_action, ll_status, lnv_assembly.ErrorText)
	This.of_SignalError( )
	Return False // Create failed => ABORT
End If

This.ib_objectCreated = True
Return True
end function

private subroutine of_setassemblyerror (long al_errortype, string as_actiontext, long al_errornumber, string as_errortext);
//*----------------------------------------------------------------------------------------------*/
//* PRIVATE of_setAssemblyError
//* Sets error description for specified error condition report by an assembly function
//*----------------------------------------------------------------------------------------------*/

String ls_error
ls_error = as_actionText + " failed.~r~n"
ls_error += "Error Number: " + String(al_errorNumber) + "."
If Len(Trim(as_errorText)) > 0 Then
	ls_error += "~r~nError Text: " + as_errorText
End If

This.il_ErrorType = al_errorType
This.is_ErrorText = ls_error
This.il_ErrorNumber = al_errorNumber
end subroutine

public subroutine of_geterrorhandler (ref powerobject apo_currenthandler, ref string as_currentevent);
//*-------------------------------------------------------------------------*/
//* PUBLIC of_GetErrorHandler
//* Return as REF-parameters current error handler (incl. event)
//*-------------------------------------------------------------------------*/

apo_currentHandler = This.ipo_errorHandler
as_currentEvent = This.is_errorEvent
end subroutine

public subroutine of_reseterrorhandler ();
//*---------------------------------------------------*/
//* PUBLIC of_ResetErrorHandler
//* Removes current error handler (incl. event)
//*---------------------------------------------------*/

SetNull(This.ipo_errorHandler)
SetNull(This.is_errorEvent)
end subroutine

public function string of_hashpassword (string as_password);
//*-----------------------------------------------------------------*/
//*  .NET function : HashPassword
//*   Argument:
//*              String as_password
//*   Return : String
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
String ls_result

/* Set the dotnet function name */
ls_function = "HashPassword"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ls_result)
		Return ls_result
	End If

	/* Trigger the dotnet function */
	ls_result = This.hashpassword(as_password)
	Return ls_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ls_result)
	Return ls_result
End Try
end function

public function boolean of_verifypassword (string as_password, string as_encodedhash);
//*-----------------------------------------------------------------*/
//*  .NET function : VerifyPassword
//*   Argument:
//*              String as_password
//*              String as_encodedhash
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "VerifyPassword"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.verifypassword(as_password, as_encodedhash)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_needsrehash (string as_encodedhash);
//*-----------------------------------------------------------------*/
//*  .NET function : NeedsRehash
//*   Argument:
//*              String as_encodedhash
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "NeedsRehash"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.needsrehash(as_encodedhash)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_isvalidhash (string as_encodedhash);
//*-----------------------------------------------------------------*/
//*  .NET function : IsValidHash
//*   Argument:
//*              String as_encodedhash
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "IsValidHash"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.isvalidhash(as_encodedhash)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_setparameters (long al_memorykib, long al_iterations, long al_parallelism);
//*-----------------------------------------------------------------*/
//*  .NET function : SetParameters
//*   Argument:
//*              Long al_memorykib
//*              Long al_iterations
//*              Long al_parallelism
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "SetParameters"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.setparameters(al_memorykib, al_iterations, al_parallelism)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_setvariant (string as_variant);
//*-----------------------------------------------------------------*/
//*  .NET function : SetVariant
//*   Argument:
//*              String as_variant
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "SetVariant"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.setvariant(as_variant)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_sethashlength (long al_bytes);
//*-----------------------------------------------------------------*/
//*  .NET function : SetHashLength
//*   Argument:
//*              Long al_bytes
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "SetHashLength"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.sethashlength(al_bytes)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public function boolean of_setsaltlength (long al_bytes);
//*-----------------------------------------------------------------*/
//*  .NET function : SetSaltLength
//*   Argument:
//*              Long al_bytes
//*   Return : Boolean
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Boolean lbln_result

/* Set the dotnet function name */
ls_function = "SetSaltLength"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(lbln_result)
		Return lbln_result
	End If

	/* Trigger the dotnet function */
	lbln_result = This.setsaltlength(al_bytes)
	Return lbln_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(lbln_result)
	Return lbln_result
End Try
end function

public subroutine of_setsecret (string as_secret);
//*-----------------------------------------------------------------*/
//*  .NET function : SetSecret
//*   Argument:
//*              String as_secret
//*   Return : (None)
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function

/* Set the dotnet function name */
ls_function = "SetSecret"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		Return
	End If

	/* Trigger the dotnet function */
	This.setsecret(as_secret)
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )
End Try
end subroutine

public function long of_getmemorykib ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetMemoryKiB
//*   Return : Long
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Long ll_result

/* Set the dotnet function name */
ls_function = "GetMemoryKiB"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ll_result)
		Return ll_result
	End If

	/* Trigger the dotnet function */
	ll_result = This.getmemorykib()
	Return ll_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ll_result)
	Return ll_result
End Try
end function

public function long of_getiterations ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetIterations
//*   Return : Long
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Long ll_result

/* Set the dotnet function name */
ls_function = "GetIterations"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ll_result)
		Return ll_result
	End If

	/* Trigger the dotnet function */
	ll_result = This.getiterations()
	Return ll_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ll_result)
	Return ll_result
End Try
end function

public function long of_getparallelism ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetParallelism
//*   Return : Long
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Long ll_result

/* Set the dotnet function name */
ls_function = "GetParallelism"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ll_result)
		Return ll_result
	End If

	/* Trigger the dotnet function */
	ll_result = This.getparallelism()
	Return ll_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ll_result)
	Return ll_result
End Try
end function

public function long of_gethashlength ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetHashLength
//*   Return : Long
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Long ll_result

/* Set the dotnet function name */
ls_function = "GetHashLength"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ll_result)
		Return ll_result
	End If

	/* Trigger the dotnet function */
	ll_result = This.gethashlength()
	Return ll_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ll_result)
	Return ll_result
End Try
end function

public function long of_getsaltlength ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetSaltLength
//*   Return : Long
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
Long ll_result

/* Set the dotnet function name */
ls_function = "GetSaltLength"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ll_result)
		Return ll_result
	End If

	/* Trigger the dotnet function */
	ll_result = This.getsaltlength()
	Return ll_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ll_result)
	Return ll_result
End Try
end function

public function string of_getvariant ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetVariant
//*   Return : String
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
String ls_result

/* Set the dotnet function name */
ls_function = "GetVariant"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ls_result)
		Return ls_result
	End If

	/* Trigger the dotnet function */
	ls_result = This.getvariant()
	Return ls_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ls_result)
	Return ls_result
End Try
end function

public function string of_getlasterror ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetLastError
//*   Return : String
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
String ls_result

/* Set the dotnet function name */
ls_function = "GetLastError"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ls_result)
		Return ls_result
	End If

	/* Trigger the dotnet function */
	ls_result = This.getlasterror()
	Return ls_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ls_result)
	Return ls_result
End Try
end function

public function string of_getlibraryversion ();
//*-----------------------------------------------------------------*/
//*  .NET function : GetLibraryVersion
//*   Return : String
//*-----------------------------------------------------------------*/
/* .NET  function name */
String ls_function
String ls_result

/* Set the dotnet function name */
ls_function = "GetLibraryVersion"

Try
	/* Create .NET object */
	If Not This.of_createOnDemand( ) Then
		SetNull(ls_result)
		Return ls_result
	End If

	/* Trigger the dotnet function */
	ls_result = This.getlibraryversion()
	Return ls_result
Catch(runtimeerror re_error)

	If This.ib_CrashOnException Then Throw re_error

	/*   Handle .NET error */
	This.of_SetDotNETError(ls_function, re_error.text)
	This.of_SignalError( )

	/*  Indicate error occurred */
	SetNull(ls_result)
	Return ls_result
End Try
end function

on nvo_argon2hasher.create
call super::create
TriggerEvent( this, "constructor" )
end on

on nvo_argon2hasher.destroy
TriggerEvent( this, "destructor" )
call super::destroy
end on
