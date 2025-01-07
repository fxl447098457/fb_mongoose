#pragma once
#ifndef MONGOOSE_H

#define MONGOOSE_H
#include once "crt/long.bi"
#include once "crt/ctype.bi"
#include once "crt/errno.bi"
#include once "crt/limits.bi"
#include once "crt/stdarg.bi"
#include once "crt/stddef.bi"
#include once "crt/stdio.bi"
#include once "crt/stdlib.bi"
#include once "crt/string.bi"
#include once "crt/sys/types.bi"
#include once "crt/time.bi"
#include once "crt/stdint.bi"
#include once "win/winsock2.bi"

#inclib "ws2_32"
#inclib "mbedtls"
#inclib "mbedcrypto"
#inclib "mbedx509"
#inclib "mongoose"

Extern "C"

#define MG_VERSION "7.16"
type nfds_t as culong
type socklen_t as long

type mg_str
   buf as zstring ptr
   len_ as uinteger
end type

declare function mg_str_s(byval s as const zstring ptr) as mg_str
declare function mg_str_n(byval s as const zstring ptr, byval n as uinteger) as mg_str
declare function mg_casecmp(byval s1 as const zstring ptr, byval s2 as const zstring ptr) as long
declare function mg_strcmp(byval str1 as const mg_str, byval str2 as const mg_str) as long
declare function mg_strcasecmp(byval str1 as const mg_str, byval str2 as const mg_str) as long
declare function mg_strdup(byval s as const mg_str) as mg_str
declare function mg_match(byval str_ as mg_str, byval pattern as mg_str, byval caps as mg_str ptr) as bool
declare function mg_span(byval s as mg_str, byval a as mg_str ptr, byval b as mg_str ptr, byval delim as byte) as bool
declare function mg_str_to_num(byval as mg_str, byval base as long, byval val_ as any ptr, byval val_len as uinteger) as bool

type mg_queue
   buf as zstring ptr
   size as uinteger
   tail as uinteger
   head as uinteger
end type

declare sub mg_queue_init(byval as mg_queue ptr, byval as zstring ptr, byval as uinteger)
declare function mg_queue_book(byval as mg_queue ptr, byval buf as zstring ptr ptr, byval as uinteger) as uinteger
declare sub mg_queue_add(byval as mg_queue ptr, byval as uinteger)
declare function mg_queue_next(byval as mg_queue ptr, byval as zstring ptr ptr) as uinteger
declare sub mg_queue_del(byval as mg_queue ptr, byval as uinteger)
type mg_pfn_t as sub(byval as byte, byval as any ptr)
type mg_pm_t as function(byval as mg_pfn_t, byval as any ptr, byval as va_list ptr) as uinteger
declare function mg_vxprintf(byval as sub(byval as byte, byval as any ptr), byval as any ptr, byval fmt as const zstring ptr, byval as va_list ptr) as uinteger
declare function mg_xprintf(byval fn as sub(byval as byte, byval as any ptr), byval as any ptr, byval fmt as const zstring ptr, ...) as uinteger
declare function mg_vsnprintf(byval buf as zstring ptr, byval len_ as uinteger, byval fmt as const zstring ptr, byval ap as va_list ptr) as uinteger
declare function mg_snprintf(byval as zstring ptr, byval as uinteger, byval fmt as const zstring ptr, ...) as uinteger
declare function mg_vmprintf(byval fmt as const zstring ptr, byval ap as va_list ptr) as zstring ptr
declare function mg_mprintf(byval fmt as const zstring ptr, ...) as zstring ptr
declare function mg_queue_vprintf(byval as mg_queue ptr, byval fmt as const zstring ptr, byval as va_list ptr) as uinteger
declare function mg_queue_printf(byval as mg_queue ptr, byval fmt as const zstring ptr, ...) as uinteger
declare function mg_print_base64(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_esc(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_hex(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_ip(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_ip_port(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_ip4(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_ip6(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare function mg_print_mac(byval out_ as sub(byval as byte, byval as any ptr), byval arg as any ptr, byval ap as va_list ptr) as uinteger
declare sub mg_pfn_iobuf(byval ch as byte, byval param as any ptr)
declare sub mg_pfn_stdout(byval c as byte, byval param as any ptr)

enum
   MG_LL_NONE
   MG_LL_ERROR
   MG_LL_INFO
   MG_LL_DEBUG
   MG_LL_VERBOSE
End Enum

extern mg_log_level as long
declare sub mg_log(byval fmt as const zstring ptr, ...)
Declare Sub mg_log_prefix(ByVal ll As Long, ByVal file As Const ZString Ptr, ByVal line_ As Long, ByVal fname As Const ZString Ptr)
declare sub mg_hexdump(byval buf as const any ptr, byval len_ as uinteger)
declare sub mg_log_set_fn(byval fn as mg_pfn_t, byval param as any ptr)

type mg_timer
   id as culong
   period_ms as ulongint
   expire as ulongint
   flags as ulong
   fn as sub(byval as any ptr)
   arg as any ptr
   next_ as mg_timer ptr
end type

declare sub mg_timer_init(byval head as mg_timer ptr ptr, byval timer as mg_timer ptr, byval milliseconds as ulongint, byval flags as ulong, byval fn as sub(byval as any ptr), byval arg as any ptr)
declare sub mg_timer_free(byval head as mg_timer ptr ptr, byval as mg_timer ptr)
declare sub mg_timer_poll(byval head as mg_timer ptr ptr, byval new_ms as ulongint)
declare function mg_timer_expired(byval expiration as ulongint ptr, byval period as ulongint, byval now as ulongint) as bool

enum
   MG_FS_READ = 1
   MG_FS_WRITE = 2
   MG_FS_DIR = 4
end enum

type mg_fs
   st as function(byval path as const zstring ptr, byval size as uinteger ptr, byval mtime as time_t ptr) as long
   ls as sub(byval path as const zstring ptr, byval fn as sub(byval as const zstring ptr, byval as any ptr), byval as any ptr)
   op as function(byval path as const zstring ptr, byval flags as long) as any ptr
   cl as sub(byval fd as any ptr)
   rd as function(byval fd as any ptr, byval buf as any ptr, byval len_ as uinteger) as uinteger
   wr as function(byval fd as any ptr, byval buf as const any ptr, byval len_ as uinteger) as uinteger
   sk as function(byval fd as any ptr, byval offset as uinteger) as uinteger
   mv As Function(ByVal from As Const ZString Ptr, ByVal to_ As Const ZString Ptr) As BOOL
   rm as function(byval path as const zstring ptr) as bool
   mkd as function(byval path as const zstring ptr) as bool
end type

extern mg_fs_posix as mg_fs
extern mg_fs_packed as mg_fs
extern mg_fs_fat as mg_fs

type mg_fd
   fd as any ptr
   fs as mg_fs ptr
end type

declare function mg_fs_open(byval fs as mg_fs ptr, byval path as const zstring ptr, byval flags as long) as mg_fd ptr
declare sub mg_fs_close(byval fd as mg_fd ptr)
declare function mg_fs_ls(byval fs as mg_fs ptr, byval path as const zstring ptr, byval buf as zstring ptr, byval len_ as uinteger) as bool
declare function mg_file_read(byval fs as mg_fs ptr, byval path as const zstring ptr) as mg_str
declare function mg_file_write(byval fs as mg_fs ptr, byval path as const zstring ptr, byval as const any ptr, byval as uinteger) as bool
declare function mg_file_printf(byval fs as mg_fs ptr, byval path as const zstring ptr, byval fmt as const zstring ptr, ...) as bool
declare function mg_unpack(byval path as const zstring ptr, byval size as uinteger ptr, byval mtime as time_t ptr) as const zstring ptr
declare function mg_unlist(byval no as uinteger) as const zstring ptr
declare function mg_unpacked(byval path as const zstring ptr) as mg_str
declare sub mg_bzero(byval buf as ubyte ptr, byval len_ as uinteger)
declare function mg_random(byval buf as any ptr, byval len_ as uinteger) as bool
declare function mg_random_str(byval buf as zstring ptr, byval len_ as uinteger) as zstring ptr
declare function mg_ntohs(byval net as ushort) as ushort
declare function mg_ntohl(byval net as ulong) as ulong
declare function mg_crc32(byval crc as ulong, byval buf as const zstring ptr, byval len_ as uinteger) as ulong
declare function mg_millis() as ulongint
declare function mg_path_is_sane(byval path as const mg_str) as bool
type mg_addr as mg_addr_
declare function mg_check_ip_acl(byval acl as mg_str, byval remote_ip as mg_addr ptr) as long
declare function mg_url_port(byval url as const zstring ptr) as ushort
declare function mg_url_is_ssl(byval url as const zstring ptr) as long
declare function mg_url_host(byval url as const zstring ptr) as mg_str
declare function mg_url_user(byval url as const zstring ptr) as mg_str
declare function mg_url_pass(byval url as const zstring ptr) as mg_str
declare function mg_url_uri(byval url as const zstring ptr) as const zstring ptr

type mg_iobuf
   buf as ubyte ptr
   size as uinteger
   len_ as uinteger
   align as uinteger
end type

declare function mg_iobuf_init(byval as mg_iobuf ptr, byval as uinteger, byval as uinteger) as long
declare function mg_iobuf_resize(byval as mg_iobuf ptr, byval as uinteger) as long
declare sub mg_iobuf_free(byval as mg_iobuf ptr)
declare function mg_iobuf_add(byval as mg_iobuf ptr, byval as uinteger, byval as const any ptr, byval as uinteger) as uinteger
declare function mg_iobuf_del(byval as mg_iobuf ptr, byval ofs as uinteger, byval len_ as uinteger) as uinteger
declare function mg_base64_update(byval input_byte as ubyte, byval buf as zstring ptr, byval len_ as uinteger) as uinteger
declare function mg_base64_final(byval buf as zstring ptr, byval len_ as uinteger) as uinteger
declare function mg_base64_encode(byval p as const ubyte ptr, byval n as uinteger, byval buf as zstring ptr, byval as uinteger) as uinteger
declare function mg_base64_decode(byval src as const zstring ptr, byval n as uinteger, byval dst as zstring ptr, byval as uinteger) as uinteger

type mg_md5_ctx
   buf(0 to 3) as ulong
   bits(0 to 1) as ulong
   in(0 to 63) as ubyte
end type

declare sub mg_md5_init(byval c as mg_md5_ctx ptr)
declare sub mg_md5_update(byval c as mg_md5_ctx ptr, byval data_ as const ubyte ptr, byval len_ as uinteger)
declare sub mg_md5_final(byval c as mg_md5_ctx ptr, byval as ubyte ptr)

type mg_sha1_ctx
   state(0 to 4) as ulong
   count(0 to 1) as ulong
   buffer(0 to 63) as ubyte
end type

declare sub mg_sha1_init(byval as mg_sha1_ctx ptr)
declare sub mg_sha1_update(byval as mg_sha1_ctx ptr, byval data_ as const ubyte ptr, byval len_ as uinteger)
declare sub mg_sha1_final(byval digest as ubyte ptr, byval as mg_sha1_ctx ptr)

type mg_sha256_ctx
   state(0 to 7) as ulong
   bits as ulongint
   len_ as ulong
   buffer(0 to 63) as ubyte
end type

declare sub mg_sha256_init(byval as mg_sha256_ctx ptr)
declare sub mg_sha256_update(byval as mg_sha256_ctx ptr, byval data_ as const ubyte ptr, byval len_ as uinteger)
declare sub mg_sha256_final(byval digest as ubyte ptr, byval as mg_sha256_ctx ptr)
declare sub mg_hmac_sha256(byval dst as ubyte ptr, byval key as ubyte ptr, byval keysz as uinteger, byval data_ as ubyte ptr, byval datasz as uinteger)
extern X25519_BASE_POINT(0 to 31) as const ubyte
declare function mg_tls_x25519(byval out_ as ubyte ptr, byval scalar as const ubyte ptr, byval x1 as const ubyte ptr, byval clamp as long) as long

type aes_context
   mode as long
   rounds as long
   rk as ulong ptr
   buf(0 to 67) as ulong
end type

declare function mg_gcm_initialize() as long
declare function mg_aes_gcm_encrypt(byval output as ubyte ptr, byval input as const ubyte ptr, byval input_length as uinteger, byval key as const ubyte ptr, byval key_len as const uinteger, byval iv as const ubyte ptr, byval iv_len as const uinteger, byval aead as ubyte ptr, byval aead_len as uinteger, byval tag as ubyte ptr, byval tag_len as const uinteger) as long
declare function mg_aes_gcm_decrypt(byval output as ubyte ptr, byval input as const ubyte ptr, byval input_length as uinteger, byval key as const ubyte ptr, byval key_len as const uinteger, byval iv as const ubyte ptr, byval iv_len as const uinteger) as long
type MG_UECC_Curve as const MG_UECC_Curve_t ptr
declare function mg_uecc_secp256r1() as MG_UECC_Curve
type MG_UECC_RNG_Function as function(byval dest as ubyte ptr, byval size as ulong) as long
declare sub mg_uecc_set_rng(byval rng_function as MG_UECC_RNG_Function)
declare function mg_uecc_get_rng() as MG_UECC_RNG_Function
declare function mg_uecc_curve_private_key_size(byval curve as MG_UECC_Curve) as long
declare function mg_uecc_curve_public_key_size(byval curve as MG_UECC_Curve) as long
declare function mg_uecc_make_key(byval public_key as ubyte ptr, byval private_key as ubyte ptr, byval curve as MG_UECC_Curve) as long
declare function mg_uecc_shared_secret(byval public_key as const ubyte ptr, byval private_key as const ubyte ptr, byval secret as ubyte ptr, byval curve as MG_UECC_Curve) as long
declare sub mg_uecc_compress(byval public_key as const ubyte ptr, byval compressed as ubyte ptr, byval curve as MG_UECC_Curve)
declare sub mg_uecc_decompress(byval compressed as const ubyte ptr, byval public_key as ubyte ptr, byval curve as MG_UECC_Curve)
declare function mg_uecc_valid_public_key(byval public_key as const ubyte ptr, byval curve as MG_UECC_Curve) as long
declare function mg_uecc_compute_public_key(byval private_key as const ubyte ptr, byval public_key as ubyte ptr, byval curve as MG_UECC_Curve) as long
declare function mg_uecc_sign(byval private_key as const ubyte ptr, byval message_hash as const ubyte ptr, byval hash_size as ulong, byval signature as ubyte ptr, byval curve as MG_UECC_Curve) as long

type MG_UECC_HashContext
   init_hash as sub(byval context as const MG_UECC_HashContext ptr)
   update_hash as sub(byval context as const MG_UECC_HashContext ptr, byval message as const ubyte ptr, byval message_size as ulong)
   finish_hash as sub(byval context as const MG_UECC_HashContext ptr, byval hash_result as ubyte ptr)
   block_size as ulong
   result_size as ulong
   tmp as ubyte ptr
end type

declare function mg_uecc_sign_deterministic(byval private_key as const ubyte ptr, byval message_hash as const ubyte ptr, byval hash_size as ulong, byval hash_context as const MG_UECC_HashContext ptr, byval signature as ubyte ptr, byval curve as MG_UECC_Curve) as long
declare function mg_uecc_verify(byval public_key as const ubyte ptr, byval message_hash as const ubyte ptr, byval hash_size as ulong, byval signature as const ubyte ptr, byval curve as MG_UECC_Curve) as long
type wordcount_t as byte
type bitcount_t as short
type cmpresult_t as byte

#if defined(__FB_64BIT__) and (defined(__FB_WIN32__) or defined(__FB_UNIX__))
   type mg_uecc_word_t as ulongint
#else
   type mg_uecc_word_t as ulong
   type mg_uecc_dword_t as ulongint
#endif

declare function mg_chacha20_poly1305_encrypt(byval cipher_text as ubyte ptr, byval key as const ubyte ptr, byval nonce as const ubyte ptr, byval ad as const ubyte ptr, byval ad_size as uinteger, byval plain_text as const ubyte ptr, byval plain_text_size as uinteger) as uinteger
declare function mg_chacha20_poly1305_decrypt(byval plain_text as ubyte ptr, byval key as const ubyte ptr, byval nonce as const ubyte ptr, byval cipher_text as const ubyte ptr, byval cipher_text_size as uinteger) as uinteger
type mg_connection as mg_connection_
type mg_event_handler_t as sub(byval as mg_connection ptr, byval ev as long, byval ev_data as any ptr)
declare sub mg_call(byval c as mg_connection ptr, byval ev as long, byval ev_data as any ptr)
declare sub mg_error(byval c as mg_connection ptr, byval fmt as const zstring ptr, ...)

enum
   MG_EV_ERROR
   MG_EV_OPEN
   MG_EV_POLL
   MG_EV_RESOLVE
   MG_EV_CONNECT
   MG_EV_ACCEPT
   MG_EV_TLS_HS
   MG_EV_READ
   MG_EV_WRITE
   MG_EV_CLOSE
   MG_EV_HTTP_HDRS
   MG_EV_HTTP_MSG
   MG_EV_WS_OPEN
   MG_EV_WS_MSG
   MG_EV_WS_CTL
   MG_EV_MQTT_CMD
   MG_EV_MQTT_MSG
   MG_EV_MQTT_OPEN
   MG_EV_SNTP_TIME
   MG_EV_WAKEUP
   MG_EV_USER
end enum

type mg_dns
   url as const zstring ptr
   c as mg_connection ptr
end type

type mg_addr_
   ip(0 to 15) as ubyte
   port as ushort
   scope_id as ubyte
   is_ip6 as bool
end type

type mg_tcpip_if as mg_tcpip_if_

type mg_mgr
   conns as mg_connection ptr
   dns4 as mg_dns
   dns6 as mg_dns
   dnstimeout as long
   use_dns6 as bool
   nextid as culong
   timerid as culong
   userdata as any ptr
   tls_ctx as any ptr
   mqtt_id as ushort
   active_dns_requests as any ptr
   timers as mg_timer ptr
   epoll_fd as long
   ifp as mg_tcpip_if ptr
   extraconnsize as uinteger
   pipe as SOCKET
end type

type mg_connection_
   next_ as mg_connection ptr
   mgr as mg_mgr ptr
   loc as mg_addr
   as mg_addr rem
   fd as any ptr
   id as culong
   recv as mg_iobuf
   send as mg_iobuf
   prof as mg_iobuf
   rtls as mg_iobuf
   fn as mg_event_handler_t
   fn_data as any ptr
   pfn as mg_event_handler_t
   pfn_data as any ptr
   data_ as zstring * 32
   tls as any ptr
   is_listening : 1 as ulong
   is_client : 1 as ulong
   is_accepted : 1 as ulong
   is_resolving : 1 as ulong
   is_arplooking : 1 as ulong
   is_connecting : 1 as ulong
   is_tls : 1 as ulong
   is_tls_hs : 1 as ulong
   is_udp : 1 as ulong
   is_websocket : 1 as ulong
   is_mqtt5 : 1 as ulong
   is_hexdumping : 1 as ulong
   is_draining : 1 as ulong
   is_closing : 1 as ulong
   is_full : 1 as ulong
   is_resp : 1 as ulong
   is_readable : 1 as ulong
   is_writable : 1 as ulong
end type

declare sub mg_mgr_poll(byval as mg_mgr ptr, byval ms as long)
declare sub mg_mgr_init(byval as mg_mgr ptr)
declare sub mg_mgr_free(byval as mg_mgr ptr)
declare function mg_listen(byval as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare function mg_connect(byval as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare function mg_wrapfd(byval mgr as mg_mgr ptr, byval fd as long, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare sub mg_connect_resolved(byval as mg_connection ptr)
declare function mg_send(byval as mg_connection ptr, byval as const any ptr, byval as uinteger) as bool
declare function mg_printf(byval as mg_connection ptr, byval fmt as const zstring ptr, ...) as uinteger
declare function mg_vprintf(byval as mg_connection ptr, byval fmt as const zstring ptr, byval ap as va_list ptr) as uinteger
declare function mg_aton(byval str_ as mg_str, byval addr as mg_addr ptr) as bool
declare function mg_alloc_conn(byval as mg_mgr ptr) as mg_connection ptr
declare sub mg_close_conn(byval c as mg_connection ptr)
declare function mg_open_listener(byval c as mg_connection ptr, byval url as const zstring ptr) as bool
declare function mg_wakeup(byval as mg_mgr ptr, byval id as culong, byval buf as const any ptr, byval len_ as uinteger) as bool
declare function mg_wakeup_init(byval as mg_mgr ptr) as bool
declare function mg_timer_add(byval mgr as mg_mgr ptr, byval milliseconds as ulongint, byval flags as ulong, byval fn as sub(byval as any ptr), byval arg as any ptr) as mg_timer ptr

type mg_http_header
   name_ as mg_str
   value as mg_str
end type

type mg_http_message
   method as mg_str
   uri as mg_str
   query as mg_str
   proto as mg_str
   headers(0 to 29) as mg_http_header
   body as mg_str
   head as mg_str
   message as mg_str
end type

type mg_http_serve_opts
   root_dir as const zstring ptr
   ssi_pattern as const zstring ptr
   extra_headers as const zstring ptr
   mime_types as const zstring ptr
   page404 as const zstring ptr
   fs as mg_fs ptr
end type

type mg_http_part
   name_ as mg_str
   filename as mg_str
   body as mg_str
end type

declare function mg_http_parse(byval s as const zstring ptr, byval len_ as uinteger, byval as mg_http_message ptr) as long
declare function mg_http_get_request_len(byval buf as const ubyte ptr, byval buf_len as uinteger) as long
declare sub mg_http_printf_chunk(byval cnn as mg_connection ptr, byval fmt as const zstring ptr, ...)
declare sub mg_http_write_chunk(byval c as mg_connection ptr, byval buf as const zstring ptr, byval len_ as uinteger)
declare sub mg_http_delete_chunk(byval c as mg_connection ptr, byval hm as mg_http_message ptr)
declare function mg_http_listen(byval as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare function mg_http_connect(byval as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare sub mg_http_serve_dir(byval as mg_connection ptr, byval hm as mg_http_message ptr, byval as const mg_http_serve_opts ptr)
declare sub mg_http_serve_file(byval as mg_connection ptr, byval hm as mg_http_message ptr, byval path as const zstring ptr, byval as const mg_http_serve_opts ptr)
declare sub mg_http_reply(byval as mg_connection ptr, byval status_code as long, byval headers as const zstring ptr, byval body_fmt as const zstring ptr, ...)
declare function mg_http_get_header(byval as mg_http_message ptr, byval name_ as const zstring ptr) as mg_str ptr
declare function mg_http_var(byval buf as mg_str, byval name_ as mg_str) as mg_str
declare function mg_http_get_var(byval as const mg_str ptr, byval name_ as const zstring ptr, byval as zstring ptr, byval as uinteger) as long
declare function mg_url_decode(byval s as const zstring ptr, byval n as uinteger, byval to as zstring ptr, byval to_len as uinteger, byval form as long) as long
declare function mg_url_encode(byval s as const zstring ptr, byval n as uinteger, byval buf as zstring ptr, byval len_ as uinteger) as uinteger
declare sub mg_http_creds(byval as mg_http_message ptr, byval as zstring ptr, byval as uinteger, byval as zstring ptr, byval as uinteger)
declare function mg_http_upload(byval c as mg_connection ptr, byval hm as mg_http_message ptr, byval fs as mg_fs ptr, byval dir as const zstring ptr, byval max_size as uinteger) as clong
declare sub mg_http_bauth(byval as mg_connection ptr, byval user as const zstring ptr, byval pass as const zstring ptr)
declare function mg_http_get_header_var(byval s as mg_str, byval v as mg_str) as mg_str
declare function mg_http_next_multipart(byval as mg_str, byval as uinteger, byval as mg_http_part ptr) as uinteger
declare function mg_http_status(byval hm as const mg_http_message ptr) as long
declare sub mg_hello(byval url as const zstring ptr)
declare sub mg_http_serve_ssi(byval c as mg_connection ptr, byval root as const zstring ptr, byval fullpath as const zstring ptr)

type mg_tls_opts
   ca as mg_str
   cert as mg_str
   key as mg_str
   name_ as mg_str
   skip_verification as long
end type

declare sub mg_tls_init(byval as mg_connection ptr, byval opts as const mg_tls_opts ptr)
declare sub mg_tls_free(byval as mg_connection ptr)
declare function mg_tls_send(byval as mg_connection ptr, byval buf as const any ptr, byval len_ as uinteger) as clong
declare function mg_tls_recv(byval as mg_connection ptr, byval buf as any ptr, byval len_ as uinteger) as clong
declare function mg_tls_pending(byval as mg_connection ptr) as uinteger
declare sub mg_tls_handshake(byval as mg_connection ptr)
declare sub mg_tls_ctx_init(byval as mg_mgr ptr)
declare sub mg_tls_ctx_free(byval as mg_mgr ptr)

enum
   MG_IO_ERR = -1
   MG_IO_WAIT = -2
   MG_IO_RESET = -3
end enum

declare function mg_io_send(byval c as mg_connection ptr, byval buf as const any ptr, byval len_ as uinteger) as clong
declare function mg_io_recv(byval c as mg_connection ptr, byval buf as any ptr, byval len_ as uinteger) as clong

type mg_ws_message
   data_ as mg_str
   flags as ubyte
end type

declare function mg_ws_connect(byval as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr, byval fmt as const zstring ptr, ...) as mg_connection ptr
declare sub mg_ws_upgrade(byval as mg_connection ptr, byval as mg_http_message ptr, byval fmt as const zstring ptr, ...)
declare function mg_ws_send(byval as mg_connection ptr, byval buf as const any ptr, byval len_ as uinteger, byval op as long) as uinteger
declare function mg_ws_wrap(byval as mg_connection ptr, byval len_ as uinteger, byval op as long) as uinteger
declare function mg_ws_printf(byval c as mg_connection ptr, byval op as long, byval fmt as const zstring ptr, ...) as uinteger
declare function mg_ws_vprintf(byval c as mg_connection ptr, byval op as long, byval fmt as const zstring ptr, byval as va_list ptr) as uinteger
declare function mg_sntp_connect(byval mgr as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare sub mg_sntp_request(byval c as mg_connection ptr)
declare function mg_sntp_parse(byval buf as const ubyte ptr, byval len_ as uinteger) as longint
declare function mg_now() as ulongint

enum
   MQTT_PROP_TYPE_BYTE
   MQTT_PROP_TYPE_STRING
   MQTT_PROP_TYPE_STRING_PAIR
   MQTT_PROP_TYPE_BINARY_DATA
   MQTT_PROP_TYPE_VARIABLE_INT
   MQTT_PROP_TYPE_INT
   MQTT_PROP_TYPE_SHORT
end enum

enum
   MQTT_OK
   MQTT_INCOMPLETE
   MQTT_MALFORMED
end enum

type mg_mqtt_prop
   id as ubyte
   iv as ulong
   key as mg_str
   val_ as mg_str
end type

type mg_mqtt_opts
   user as mg_str
   pass as mg_str
   client_id as mg_str
   topic as mg_str
   message as mg_str
   qos as ubyte
   version as ubyte
   keepalive as ushort
   retransmit_id as ushort
   retain as bool
   clean as bool
   props as mg_mqtt_prop ptr
   num_props as uinteger
   will_props as mg_mqtt_prop ptr
   num_will_props as uinteger
end type

type mg_mqtt_message
   topic as mg_str
   data_ as mg_str
   dgram as mg_str
   id as ushort
   cmd as ubyte
   qos as ubyte
   ack as ubyte
   props_start as uinteger
   props_size as uinteger
end type

declare function mg_mqtt_connect(byval as mg_mgr ptr, byval url as const zstring ptr, byval opts as const mg_mqtt_opts ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare function mg_mqtt_listen(byval mgr as mg_mgr ptr, byval url as const zstring ptr, byval fn as mg_event_handler_t, byval fn_data as any ptr) as mg_connection ptr
declare sub mg_mqtt_login(byval c as mg_connection ptr, byval opts as const mg_mqtt_opts ptr)
declare function mg_mqtt_pub(byval c as mg_connection ptr, byval opts as const mg_mqtt_opts ptr) as ushort
declare sub mg_mqtt_sub(byval as mg_connection ptr, byval opts as const mg_mqtt_opts ptr)
declare function mg_mqtt_parse(byval as const ubyte ptr, byval as uinteger, byval as ubyte, byval as mg_mqtt_message ptr) as long
declare sub mg_mqtt_send_header(byval as mg_connection ptr, byval cmd as ubyte, byval flags as ubyte, byval len_ as ulong)
declare sub mg_mqtt_ping(byval as mg_connection ptr)
declare sub mg_mqtt_pong(byval as mg_connection ptr)
declare sub mg_mqtt_disconnect(byval as mg_connection ptr, byval as const mg_mqtt_opts ptr)
declare function mg_mqtt_next_prop(byval as mg_mqtt_message ptr, byval as mg_mqtt_prop ptr, byval ofs as uinteger) as uinteger

type mg_dns_message
   txnid as ushort
   resolved as bool
   addr as mg_addr
   name_ as zstring * 256
end type

type mg_dns_header
   txnid as ushort
   flags as ushort
   num_questions as ushort
   num_answers as ushort
   num_authority_prs as ushort
   num_other_prs as ushort
end type

type mg_dns_rr
   nlen as ushort
   atype as ushort
   aclass as ushort
   alen as ushort
end type

declare sub mg_resolve(byval as mg_connection ptr, byval url as const zstring ptr)
declare sub mg_resolve_cancel(byval as mg_connection ptr)
declare function mg_dns_parse(byval buf as const ubyte ptr, byval len_ as uinteger, byval as mg_dns_message ptr) as bool
declare function mg_dns_parse_rr(byval buf as const ubyte ptr, byval len_ as uinteger, byval ofs as uinteger, byval is_question as bool, byval as mg_dns_rr ptr) as uinteger

enum
   MG_JSON_TOO_DEEP = -1
   MG_JSON_INVALID = -2
   MG_JSON_NOT_FOUND = -3
end enum

declare function mg_json_get(byval json as mg_str, byval path as const zstring ptr, byval toklen as long ptr) as long
declare function mg_json_get_tok(byval json as mg_str, byval path as const zstring ptr) as mg_str
declare function mg_json_get_num(byval json as mg_str, byval path as const zstring ptr, byval v as double ptr) as bool
declare function mg_json_get_bool(byval json as mg_str, byval path as const zstring ptr, byval v as bool ptr) as bool
declare function mg_json_get_long(byval json as mg_str, byval path as const zstring ptr, byval dflt as clong) as clong
declare function mg_json_get_str(byval json as mg_str, byval path as const zstring ptr) as zstring ptr
declare function mg_json_get_hex(byval json as mg_str, byval path as const zstring ptr, byval len_ as long ptr) as zstring ptr
declare function mg_json_get_b64(byval json as mg_str, byval path as const zstring ptr, byval len_ as long ptr) as zstring ptr
declare function mg_json_unescape(byval str_ as mg_str, byval buf as zstring ptr, byval len_ as uinteger) as bool
declare function mg_json_next(byval obj as mg_str, byval ofs as uinteger, byval key as mg_str ptr, byval val_ as mg_str ptr) as uinteger
type mg_rpc as mg_rpc_

type mg_rpc_req
   head as mg_rpc ptr ptr
   rpc as mg_rpc ptr
   pfn as mg_pfn_t
   pfn_data as any ptr
   req_data as any ptr
   frame as mg_str
end type

type mg_rpc_
   next_ as mg_rpc ptr
   method as mg_str
   fn as sub(byval as mg_rpc_req ptr)
   fn_data as any ptr
end type

declare sub mg_rpc_add(byval head as mg_rpc ptr ptr, byval method_pattern as mg_str, byval handler as sub(byval as mg_rpc_req ptr), byval handler_data as any ptr)
declare sub mg_rpc_del(byval head as mg_rpc ptr ptr, byval handler as sub(byval as mg_rpc_req ptr))
declare sub mg_rpc_process(byval as mg_rpc_req ptr)
declare sub mg_rpc_ok(byval as mg_rpc_req ptr, byval fmt as const zstring ptr, ...)
declare sub mg_rpc_vok(byval as mg_rpc_req ptr, byval fmt as const zstring ptr, byval ap as va_list ptr)
declare sub mg_rpc_err(byval as mg_rpc_req ptr, byval code as long, byval fmt as const zstring ptr, ...)
declare sub mg_rpc_verr(byval as mg_rpc_req ptr, byval code as long, byval fmt as const zstring ptr, byval as va_list ptr)
declare sub mg_rpc_list(byval r as mg_rpc_req ptr)
declare function mg_ota_begin(byval new_firmware_size as uinteger) as bool
declare function mg_ota_write(byval buf as const any ptr, byval len_ as uinteger) as bool
declare function mg_ota_end() as bool

type mg_tcpip_driver
   init as function(byval as mg_tcpip_if ptr) as bool
   tx as function(byval as const any ptr, byval as uinteger, byval as mg_tcpip_if ptr) as uinteger
   rx as function(byval buf as any ptr, byval len_ as uinteger, byval as mg_tcpip_if ptr) as uinteger
   up as function(byval as mg_tcpip_if ptr) as bool
end type

type mg_tcpip_event_handler_t as sub(byval ifp as mg_tcpip_if ptr, byval ev as long, byval ev_data as any ptr)

enum
   MG_TCPIP_EV_ST_CHG
   MG_TCPIP_EV_DHCP_DNS
   MG_TCPIP_EV_DHCP_SNTP
   MG_TCPIP_EV_ARP
   MG_TCPIP_EV_TIMER_1S
   MG_TCPIP_EV_USER
end enum

type mg_tcpip_if_
   mac(0 to 5) as ubyte
   ip as ulong
   mask as ulong
   gw as ulong
   tx as mg_str
   enable_dhcp_client as bool
   enable_dhcp_server as bool
   enable_get_gateway as bool
   enable_req_dns as bool
   enable_req_sntp as bool
   enable_crc32_check as bool
   enable_mac_check as bool
   driver as mg_tcpip_driver ptr
   driver_data as any ptr
   fn as mg_tcpip_event_handler_t
   mgr as mg_mgr ptr
   recv_queue as mg_queue
   mtu as ushort
   gwmac(0 to 5) as ubyte
   now as ulongint
   timer_1000ms as ulongint
   lease_expire as ulongint
   eport as ushort
   ndrop as ulong
   nrecv as ulong
   nsent as ulong
   nerr as ulong
   state as ubyte
end type

declare sub mg_tcpip_init(byval as mg_mgr ptr, byval as mg_tcpip_if ptr)
declare sub mg_tcpip_free(byval as mg_tcpip_if ptr)
declare sub mg_tcpip_qwrite(byval buf as any ptr, byval len_ as uinteger, byval ifp as mg_tcpip_if ptr)
declare sub mg_tcpip_arp_request(byval ifp as mg_tcpip_if ptr, byval ip as ulong, byval mac as ubyte ptr)

extern mg_tcpip_driver_stm32f as mg_tcpip_driver
extern mg_tcpip_driver_w5500 as mg_tcpip_driver
extern mg_tcpip_driver_tm4c as mg_tcpip_driver
extern mg_tcpip_driver_tms570 as mg_tcpip_driver
extern mg_tcpip_driver_stm32h as mg_tcpip_driver
extern mg_tcpip_driver_imxrt as mg_tcpip_driver
extern mg_tcpip_driver_same54 as mg_tcpip_driver
extern mg_tcpip_driver_cmsis as mg_tcpip_driver
extern mg_tcpip_driver_ra as mg_tcpip_driver
extern mg_tcpip_driver_xmc as mg_tcpip_driver
extern mg_tcpip_driver_xmc7 as mg_tcpip_driver
extern mg_tcpip_driver_ppp as mg_tcpip_driver
extern mg_tcpip_driver_pico_w as mg_tcpip_driver

type mg_tcpip_spi
   spi as any ptr
   begin as sub(byval as any ptr)
   end_ as sub(byval as any ptr)
   txn as function(byval as any ptr, byval as ubyte) as ubyte
end type

type mg_phy
   read_reg as function(byval addr as ubyte, byval reg as ubyte) as ushort
   write_reg as sub(byval addr as ubyte, byval reg as ubyte, byval value as ushort)
end type

enum
   MG_PHY_LEDS_ACTIVE_HIGH = 1 shl 0
   MG_PHY_CLOCKS_MAC = 1 shl 1
end enum

enum
   MG_PHY_SPEED_10M
   MG_PHY_SPEED_100M
   MG_PHY_SPEED_1000M
end enum

declare sub mg_phy_init(byval as mg_phy ptr, byval addr as ubyte, byval config as ubyte)
declare function mg_phy_up(byval as mg_phy ptr, byval addr as ubyte, byval full_duplex as bool ptr, byval speed as ubyte ptr) as bool

type mg_tcpip_driver_ppp_data
   uart as any ptr
   reset as sub(byval as any ptr)
   tx as sub(byval as any ptr, byval as ubyte)
   rx as function(byval as any ptr) as long
   script as const zstring ptr ptr
   script_index as long
   deadline as ulongint
end type

const MG_ARCH_CUSTOM = 0
Const MG_ARCH_UNIX = 1
Const MG_ARCH_WIN32 = 2
Const MG_ARCH_ESP32 = 3
Const MG_ARCH_ESP8266 = 4
Const MG_ARCH_FREERTOS = 5
Const MG_ARCH_AZURERTOS = 6
Const MG_ARCH_ZEPHYR = 7
Const MG_ARCH_NEWLIB = 8
Const MG_ARCH_CMSIS_RTOS1 = 9
Const MG_ARCH_TIRTOS = 10
Const MG_ARCH_PICOSDK = 11
Const MG_ARCH_ARMCC = 12
Const MG_ARCH_CMSIS_RTOS2 = 13
Const MG_ARCH_RTTHREAD = 14
Const MG_ARCH_ARMCGT = 15
#define MG_BIG_ENDIAN ((*CPtr(UShort Ptr, @!"\0\255")) < &h100)
#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MG_INVALID_SOCKET INVALID_SOCKET
#define MG_SOCKET_TYPE SOCKET
#define poll(a, b, c) WSAPoll((a), (b), (c))
#define MG_DIRSEP Asc(!"\\")
#define MG_PATH_MAX FILENAME_MAX
#define MG_SOCK_ERR(errcode) IIf((errcode) < 0, WSAGetLastError(), 0)
#define MG_SOCK_PENDING(errcode) (((errcode) < 0) AndAlso (((WSAGetLastError() = WSAEINTR) OrElse (WSAGetLastError() = WSAEINPROGRESS)) OrElse (WSAGetLastError() = WSAEWOULDBLOCK)))
#define MG_SOCK_RESET(errcode) (((errcode) < 0) AndAlso (WSAGetLastError() = WSAECONNRESET))
#define realpath(a, b) _fullpath((b), (a), MG_PATH_MAX)
#define timegm(x) _mkgmtime(x)
#define S_ISDIR(x) (((x) And _S_IFMT) = _S_IFDIR)
Const MG_ENABLE_DIRLIST = 1
Const SIGPIPE = 0
Const MG_ENABLE_POSIX_FS = 1
Const MG_IO_SIZE = 16384
Const MG_ENABLE_LOG = 1
Const MG_ENABLE_CUSTOM_LOG = 0
Const MG_ENABLE_TCPIP = 0
Const MG_ENABLE_LWIP = 0
const MG_ENABLE_FREERTOS_TCP = 0
const MG_ENABLE_RL = 0
const MG_ENABLE_SOCKET = MG_ENABLE_TCPIP = 0
const MG_ENABLE_POLL = 0
const MG_ENABLE_EPOLL = 0
const MG_ENABLE_FATFS = 0
const MG_ENABLE_SSI = 0
const MG_ENABLE_IPV6 = 0
const MG_IPV6_V6ONLY = 0
Const MG_ENABLE_MD5 = 1
Const MG_ENABLE_WINSOCK = 1
Const MG_ENABLE_CUSTOM_RANDOM = 0
Const MG_ENABLE_CUSTOM_MILLIS = 0
Const MG_ENABLE_PACKED_FS = 0
Const MG_ENABLE_ASSERT = 0
Const MG_MAX_RECV_SIZE = (Cast(culong, 3) * Cast(culong, 1024)) * Cast(culong, 1024)
Const MG_DATA_SIZE = 32
Const MG_MAX_HTTP_HEADERS = 30
#define MG_HTTP_INDEX "index.html"
Const MG_SOCK_LISTEN_BACKLOG_SIZE = 128
#define MG_SOCKET_ERRNO errno
#define MG_EPOLL_ADD(c)
#define MG_EPOLL_MOD(c, wr)
Const MG_ENABLE_PROFILE = 0
Const MG_ENABLE_TCPIP_DRIVER_INIT = 1
#define MG_TCPIP_IP MG_IPV4(0, 0, 0, 0)
#define MG_TCPIP_MASK MG_IPV4(0, 0, 0, 0)
#define MG_TCPIP_GW MG_IPV4(0, 0, 0, 0)
#define MG_SET_MAC_ADDRESS(mac)
#define MG_SET_WIFI_CREDS(ssid, pass)
Const MG_ENABLE_TCPIP_PRINT_DEBUG_STATS = 0
#define MG_ESC(str) mg_print_esc, 0, (str)
#define mg_log_set(level_) Scope : mg_log_level = (level_) : End Scope
#define MG_INFO(args) mg_log(MG_LL_INFO, args)
#define MG_DEBUG(args) mg_log(MG_LL_DEBUG, args)
#define MG_VERBOSE(args) mg_log(MG_LL_VERBOSE, args)
Const MG_TIMER_ONCE = 0
Const MG_TIMER_REPEAT = 1
Const MG_TIMER_RUN_NOW = 2
#define mg_htonl(x) mg_ntohl(x)
#define MG_U32(a, b, c, d) CULng(CULng(CULng(CULng(CULng((a) And 255) Shl 24) Or CULng(CULng((b) And 255) Shl 16)) Or CULng(CULng((c) And 255) Shl 8)) Or CULng((d) And 255))
#define MG_IPV4(a, b, c, d) mg_htonl(MG_U32(a, b, c, d))
#define MG_U8P(ADDR) CPtr(UByte Ptr, (ADDR))
#define MG_IPADDR_PARTS(ADDR) MG_U8P(ADDR)[0], MG_U8P(ADDR)[1], MG_U8P(ADDR)[2], MG_U8P(ADDR)[3]
#define MG_LOAD_BE16(p) CUShort((MG_U8P(p)[0] Shl 8u) Or MG_U8P(p)[1])
#define MG_LOAD_BE24(p) CULng(((MG_U8P(p)[0] Shl 16u) Or (MG_U8P(p)[1] Shl 8u)) Or MG_U8P(p)[2])
#macro MG_STORE_BE16(p, n)
   Scope
      MG_U8P(p)[0] = ((n) Shr 8u) And 255
      MG_U8P(p)[1] = (n) And 255
   End Scope
#endmacro
#define MG_REG(x) CPtr(ULong Ptr, (x))[0]
#define MG_BIT(x) culng(culng(1u) shl (x))
#define MG_SET_BITS(R, CLRMASK, SETMASK) scope : (R) = ((R) and (not (CLRMASK))) or (SETMASK) : end scope
#define MG_ROUND_UP(x, a) iif((a) = 0, (x), ((((x) + (a)) - 1) / (a)) * (a))
#define MG_ROUND_DOWN(x, a) iif((a) = 0, (x), ((x) / (a)) * (a))

#define MG_DSB()
#macro LIST_ADD_HEAD(type_, head_, elem_)
   scope
      (elem_)->next_ = *head_
      (*(head_)) = (elem_)
   end scope
#endmacro
#macro LIST_ADD_TAIL(type_, head_, elem_)
   scope
      (type_ * (*h)) = head_
      while (*h) <> NULL
         h = @(*h)->next_
      wend
      (*h) = (elem_)
   end scope
#endmacro
#macro LIST_DELETE(type_, head_, elem_)
   scope
      (type_ * (*h)) = head_
      while (*h) <> (elem_)
         h = @(*h)->next_
      wend
      (*h) = (elem_)->next_
   end scope
#endmacro
#define TLS_X15519_H
const X25519_BYTES = 32
#define TLS_AES128_H
const GCM_AUTH_FAILURE = &h55555555
const MG_UECC_SUPPORTS_secp256r1 = 1
#define _UECC_H_
const mg_uecc_arch_other = 0
const mg_uecc_x86 = 1
const mg_uecc_x86_64 = 2
const mg_uecc_arm = 3
const mg_uecc_arm_thumb = 4
const mg_uecc_arm_thumb2 = 5
const mg_uecc_arm64 = 6
const mg_uecc_avr = 7
const MG_UECC_OPTIMIZATION_LEVEL = 2
const MG_UECC_SQUARE_FUNC = 0
const MG_UECC_VLI_NATIVE_LITTLE_ENDIAN = 0
const MG_UECC_SUPPORTS_secp160r1 = 0
const MG_UECC_SUPPORTS_secp192r1 = 0
const MG_UECC_SUPPORTS_secp224r1 = 0
const MG_UECC_SUPPORTS_secp256k1 = 0
const MG_UECC_SUPPORT_COMPRESSED_POINT = 1
#define _UECC_TYPES_H_

#if defined(__FB_DOS__) or ((not defined(__FB_64BIT__)) and (defined(__FB_DARWIN__) or defined(__FB_WIN32__) or defined(__FB_CYGWIN__) or ((not defined(__FB_ARM__)) and (defined(__FB_LINUX__) or defined(__FB_FREEBSD__) or defined(__FB_OPENBSD__) or defined(__FB_NETBSD__)))))
   const MG_UECC_PLATFORM = mg_uecc_x86
#elseif defined(__FB_64BIT__) and (defined(__FB_DARWIN__) or defined(__FB_WIN32__) or defined(__FB_CYGWIN__) or ((not defined(__FB_ARM__)) and (defined(__FB_LINUX__) or defined(__FB_FREEBSD__) or defined(__FB_OPENBSD__) or defined(__FB_NETBSD__))))
   const MG_UECC_PLATFORM = mg_uecc_x86_64
#elseif defined(__FB_64BIT__) and defined(__FB_ARM__) and (defined(__FB_LINUX__) or defined(__FB_FREEBSD__) or defined(__FB_OPENBSD__) or defined(__FB_NETBSD__))
   const MG_UECC_PLATFORM = mg_uecc_arm64
#endif

#if (not defined(__FB_64BIT__)) and defined(__FB_ARM__) and (defined(__FB_LINUX__) or defined(__FB_FREEBSD__) or defined(__FB_OPENBSD__) or defined(__FB_NETBSD__))
   const MG_UECC_PLATFORM = mg_uecc_arm
   const MG_UECC_ARM_USE_UMAAL = 1
#else
   const MG_UECC_ARM_USE_UMAAL = 0
#endif

#if defined(__FB_64BIT__) and (defined(__FB_WIN32__) or defined(__FB_UNIX__))
   const MG_UECC_WORD_SIZE = 8
   const HIGH_BIT_SET = &h8000000000000000u
   const MG_UECC_WORD_BITS = 64
   const MG_UECC_WORD_BITS_SHIFT = 6
   const MG_UECC_WORD_BITS_MASK = &h03F
#else
   const MG_UECC_WORD_SIZE = 4
   const HIGH_BIT_SET = &h80000000
   const MG_UECC_WORD_BITS = 32
   const MG_UECC_WORD_BITS_SHIFT = 5
   const MG_UECC_WORD_BITS_MASK = &h01F
#endif

#define _UECC_VLI_H_
const MG_UECC_ENABLE_VLI_API = 0
#define __PORTABLE_8439_H
#define PORTABLE_8439_DECL

const RFC_8439_TAG_SIZE = 16
const RFC_8439_KEY_SIZE = 32
const RFC_8439_NONCE_SIZE = 12
const MG_TLS_NONE = 0
const MG_TLS_MBED = 1
const MG_TLS_OPENSSL = 2
const MG_TLS_WOLFSSL = 5
const MG_TLS_BUILTIN = 3
const MG_TLS_CUSTOM = 4
const MG_TLS = MG_TLS_NONE
const WEBSOCKET_OP_CONTINUE = 0
const WEBSOCKET_OP_TEXT = 1
const WEBSOCKET_OP_BINARY = 2
const WEBSOCKET_OP_CLOSE = 8
const WEBSOCKET_OP_PING = 9
const WEBSOCKET_OP_PONG = 10
const MQTT_CMD_CONNECT = 1
const MQTT_CMD_CONNACK = 2
const MQTT_CMD_PUBLISH = 3
const MQTT_CMD_PUBACK = 4
const MQTT_CMD_PUBREC = 5
const MQTT_CMD_PUBREL = 6
const MQTT_CMD_PUBCOMP = 7
const MQTT_CMD_SUBSCRIBE = 8
const MQTT_CMD_SUBACK = 9
const MQTT_CMD_UNSUBSCRIBE = 10
const MQTT_CMD_UNSUBACK = 11
const MQTT_CMD_PINGREQ = 12
const MQTT_CMD_PINGRESP = 13
const MQTT_CMD_DISCONNECT = 14
const MQTT_CMD_AUTH = 15
const MQTT_PROP_PAYLOAD_FORMAT_INDICATOR = &h01
const MQTT_PROP_MESSAGE_EXPIRY_INTERVAL = &h02
const MQTT_PROP_CONTENT_TYPE = &h03
const MQTT_PROP_RESPONSE_TOPIC = &h08
const MQTT_PROP_CORRELATION_DATA = &h09
const MQTT_PROP_SUBSCRIPTION_IDENTIFIER = &h0B
const MQTT_PROP_SESSION_EXPIRY_INTERVAL = &h11
const MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER = &h12
const MQTT_PROP_SERVER_KEEP_ALIVE = &h13
const MQTT_PROP_AUTHENTICATION_METHOD = &h15
const MQTT_PROP_AUTHENTICATION_DATA = &h16
const MQTT_PROP_REQUEST_PROBLEM_INFORMATION = &h17
const MQTT_PROP_WILL_DELAY_INTERVAL = &h18
const MQTT_PROP_REQUEST_RESPONSE_INFORMATION = &h19
const MQTT_PROP_RESPONSE_INFORMATION = &h1A
const MQTT_PROP_SERVER_REFERENCE = &h1C
const MQTT_PROP_REASON_STRING = &h1F
const MQTT_PROP_RECEIVE_MAXIMUM = &h21
const MQTT_PROP_TOPIC_ALIAS_MAXIMUM = &h22
const MQTT_PROP_TOPIC_ALIAS = &h23
const MQTT_PROP_MAXIMUM_QOS = &h24
const MQTT_PROP_RETAIN_AVAILABLE = &h25
const MQTT_PROP_USER_PROPERTY = &h26
const MQTT_PROP_MAXIMUM_PACKET_SIZE = &h27
const MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE = &h28
const MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE = &h29
const MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE = &h2A
const MG_JSON_MAX_DEPTH = 30
const MG_OTA_NONE = 0
const MG_OTA_STM32H5 = 1
const MG_OTA_STM32H7 = 2
const MG_OTA_STM32H7_DUAL_CORE = 3
const MG_OTA_STM32F = 4
const MG_OTA_CH32V307 = 100
const MG_OTA_U2A = 200
const MG_OTA_RT1020 = 300
const MG_OTA_RT1060 = 301
const MG_OTA_RT1064 = 302
const MG_OTA_RT1170 = 303
const MG_OTA_MCXN = 310
const MG_OTA_FLASH = 900
const MG_OTA_ESP32 = 910
const MG_OTA_PICOSDK = 920
const MG_OTA_CUSTOM = 1000
const MG_OTA = MG_OTA_NONE
const MG_TCPIP_MTU_DEFAULT = 1500
const MG_TCPIP_STATE_DOWN = 0
const MG_TCPIP_STATE_UP = 1
const MG_TCPIP_STATE_REQ = 2
const MG_TCPIP_STATE_IP = 3
const MG_TCPIP_STATE_READY = 4
#define MG_PROF_INIT(c)
#define MG_PROF_FREE(c)
#define MG_PROF_ADD(c, name_)
#define MG_PROF_DUMP(c)

end extern
#endif
