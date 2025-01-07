'下面内容由 VisualFreeBasic 5.9.4 自动产生，请勿自己修改
'[VFB_PROJECT_SETUP_START]
'NumObjects=1
'ProjectName=client
'CompilationMode=0
'CompilationDebug=0
'ProjectType=GUI
'UseGDIPlus=0
'ShowConsole=1
'MultiLanguage=0
'OmitInformation=0
'StartupIcon=
'UseWinXPthemes=1
'StrUnicode=0
'UseAdminPriv=0
'DeleteGeneratedCode=1
'Namespace=0
'AutoAdd64=0
'AddCompOps=
'LastRunFilename=client
'Major=0
'Minor=0
'Revision=0
'Build=0
'FileMajor=0
'FileMinor=0
'FileRevision=0
'FileBuild=27
'AutoIncrement=3
'DefaultCompiler=32
'Comments=
'CompanyName=
'FileDescription=
'LegalCopyrights=
'LegalTrademarks=
'ProductName=

'Module=.\client.bas|25|1602||Yes|
'[VFB_PROJECT_SETUP_END]
#include once "mongoose.bi"
#include once "crt/stdlib.bi"
#inclib "msvcr100" '/wstat32i36/'
#ifndef __FB_64BIT__
#libpath "win32"
#else
#libpath "win64"
#endif
Dim Shared s_url As  ZString Ptr = @"http://info.cern.ch/"
Dim Shared s_post_data As  ZString Ptr = NULL
Dim Shared s_timeout_ms As  ULongInt = 1500

Private Sub fn(ByVal c As mg_connection Ptr, ByVal ev As Long, ByVal ev_data As Any Ptr)
   If ev = MG_EV_OPEN Then
   *CPtr(ULongInt Ptr, @c->data_)= mg_millis() + s_timeout_ms  
   ElseIf ev = MG_EV_POLL Then
      If ((mg_millis() > (*CPtr(ULongInt Ptr, @c->data_))) AndAlso (c->is_connecting OrElse c->is_resolving)) Then
         Print "Connect timeout"
      End If
   ElseIf ev = MG_EV_CONNECT Then
      Dim host As mg_str = mg_url_host(s_url)
      If mg_url_is_ssl(s_url) Then
         Dim opts As mg_tls_opts
         opts.ca = mg_unpacked(Cast(ZString Ptr,@"/certs/ca.pem"))
         opts.name_ = mg_url_host(s_url)
         mg_tls_init(c, @opts)
      End If
      Dim content_length As Long = IIf(s_post_data, strlen(s_post_data), 0) 
    
      mg_printf(c,@!"%s %s HTTP/1.0\r\nHost: %.*s\r\nContent-Type: octet-stream\r\nContent-Length: %d\r\n\r\n", IIf(s_post_data, "POST", "GET"), mg_url_uri(s_url), CLng(host.len_), host.buf, content_length)
      mg_send(c, Cast(Any Ptr, s_post_data), content_length)
   ElseIf ev = MG_EV_HTTP_MSG Then
      Dim hm As mg_http_message Ptr =CPtr(mg_http_message Ptr, ev_data)
     printf("%.*s", CLng(hm->message.len_), *hm->message.buf)
     c->is_draining = 1
      *CPtr(BOOL Ptr, @c->fn_data) = True'
   ElseIf ev = MG_EV_ERROR Then
      *CPtr(BOOL Ptr, @c->fn_data) = True
   End If
End Sub

   Dim log_level As  ZString Ptr = getenv("LOG_LEVEL")
   If log_level = NULL Then
      log_level = @"4"
   End If
   Dim mgr As mg_mgr 
   Dim As BOOL done =0
   mg_log_set(MG_LL_DEBUG)
   mg_mgr_init(@mgr)  
   mg_http_connect(@mgr, s_url, Cast(Any Ptr, @fn),@done)
   While done = 0
    mg_mgr_poll(@mgr, 500)   
   Wend
    mg_mgr_free(@mgr)
 Sleep
