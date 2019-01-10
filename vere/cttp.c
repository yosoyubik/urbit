/* v/cttp.c
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <uv.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <h2o.h>
#include "all.h"
#include "vere/vere.h"


static void _cttp_cert_free(void);
static h2o_url_t _cttp_ceq_to_h2o_url(u3_creq* ceq_u);
static char* _cttp_met_to_char(c3_m met_m);
static uv_buf_t _cttp_wain_to_buf(u3_noun wan);
static c3_c* _cttp_ceq_to_host_hed(u3_creq* ceq_u);
static void timeout_cb(h2o_timer_t *entry);
int fill_body(h2o_iovec_t *reqbuf, u3_creq* ceq_u);

struct st_timeout_ctx {
    h2o_httpclient_t *client;
    h2o_timer_t _timeout;
};


// XX deduplicate with _http_vec_to_atom
/* _cttp_vec_to_atom(): convert h2o_iovec_t to atom (cord)
*/
static u3_noun
_cttp_vec_to_atom(h2o_iovec_t vec_u)
{
  return u3i_bytes(vec_u.len, (const c3_y*)vec_u.base);
}

/* _cttp_bods_free(): free body structure.
*/
static void
_cttp_bods_free(u3_hbod* bod_u)
{
  while ( bod_u ) {
    u3_hbod* nex_u = bod_u->nex_u;

    free(bod_u);
    bod_u = nex_u;
  }
}

static h2o_url_t
_cttp_ceq_to_h2o_url(u3_creq* ceq_u)
{
  c3_s por_s = ceq_u->por_s ? ceq_u->por_s :
               ( c3y == ceq_u->sec ) ? 443 : 80;

  c3_c* por_c = c3_calloc(6);
  sprintf(por_c, "%u", por_s);

  c3_s prefix_len = ( c3y == ceq_u->sec ) ? 8 : 7;
  c3_c* url_c = c3_calloc(prefix_len + strlen(ceq_u->ipf_c) + 
                          strlen(por_c) + 2); // host:port
  strcpy(url_c, ( c3y == ceq_u->sec ) ? "https://" : "http://");
  strcat(url_c, ceq_u->ipf_c);
  strcat(url_c, ":");
  strcat(url_c, por_c);

  h2o_url_t url;
  if ( h2o_url_parse(url_c, strlen(url_c), &url) ) {
    uL(fprintf(uH, "cttp: malformed url: %s\n", url_c));

    c3_assert(0);
  }

  return url;
}

static char*
_cttp_met_to_char(c3_m met_m)
{
  switch ( met_m ) {
    default: c3_assert(0); return 0;
    case c3__get:   return (char*)"GET ";      break;
    case c3__put:   return (char*)"PUT ";      break;
    case c3__post:  return (char*)"POST ";     break;
    case c3__head:  return (char*)"HEAD ";     break;
    case c3__conn:  return (char*)"CONNECT ";  break;
    case c3__delt:  return (char*)"DELETE ";   break;
    case c3__opts:  return (char*)"OPTIONS ";  break;
    case c3__trac:  return (char*)"TRACE ";    break;
  }
}

static c3_c*
_cttp_ceq_to_host_hed(u3_creq* ceq_u)
{
    c3_c* hot_c = ceq_u->hot_c ? ceq_u->hot_c : ceq_u->ipf_c;
    c3_c* hos_c;
    c3_w len_w;

    if ( ceq_u->por_c ) {
      len_w = strlen(hot_c) + strlen(ceq_u->por_c) + 2;
      hos_c = c3_calloc(len_w);
      len_w = snprintf(hos_c, len_w, "%s:%s", hot_c, ceq_u->por_c);
    }
    else {
      len_w = strlen(hot_c) + 1;
      hos_c = c3_calloc(len_w);
      len_w = snprintf(hos_c, len_w, "%s", hot_c);
    }

    return hos_c;
}


/* _cttp_bod_new(): create a data buffer
*/
static u3_hbod*
_cttp_bod_new(c3_w len_w, c3_c* hun_c)
{
  u3_hbod* bod_u = c3_malloc(1 + len_w + sizeof(*bod_u));
  bod_u->hun_y[len_w] = 0;
  bod_u->len_w = len_w;
  memcpy(bod_u->hun_y, (const c3_y*)hun_c, len_w);

  bod_u->nex_u = 0;
  return bod_u;
}

/* _cttp_bods_to_octs: translate body buffer into octet-stream noun.
*/
static u3_noun
_cttp_bods_to_octs(u3_hbod* bod_u)
{
  c3_w    len_w;
  c3_y*   buf_y;
  u3_noun cos;

  {
    u3_hbod* bid_u = bod_u;

    len_w = 0;
    while ( bid_u ) {
      len_w += bid_u->len_w;
      bid_u = bid_u->nex_u;
    }
  }
  buf_y = c3_malloc(1 + len_w);
  buf_y[len_w] = 0;

  {
    c3_y* ptr_y = buf_y;

    while ( bod_u ) {
      memcpy(ptr_y, bod_u->hun_y, bod_u->len_w);
      ptr_y += bod_u->len_w;
      bod_u = bod_u->nex_u;
    }
  }
  cos = u3i_bytes(len_w, buf_y);
  free(buf_y);
  return u3nc(len_w, cos);
}

/* _cttp_bod_from_octs(): translate octet-stream noun into body.
*/
static u3_hbod*
_cttp_bod_from_octs(u3_noun oct)
{
  c3_w len_w;

  if ( !_(u3a_is_cat(u3h(oct))) ) {     //  2GB max
    u3m_bail(c3__fail); return 0;
  }
  len_w = u3h(oct);

  {
    u3_hbod* bod_u = c3_malloc(1 + len_w + sizeof(*bod_u));
    bod_u->hun_y[len_w] = 0;
    bod_u->len_w = len_w;
    u3r_bytes(0, len_w, bod_u->hun_y, u3t(oct));

    bod_u->nex_u = 0;

    u3z(oct);
    return bod_u;
  }
}

/* _cttp_bods_to_vec(): translate body buffers to array of h2o_iovec_t
*/
static h2o_iovec_t*
_cttp_bods_to_vec(u3_hbod* bod_u, c3_w* tot_w)
{
  h2o_iovec_t* vec_u;
  c3_w len_w;

  {
    u3_hbod* bid_u = bod_u;
    len_w = 0;

    while( bid_u ) {
      len_w++;
      bid_u = bid_u->nex_u;
    }
  }

  if ( 0 == len_w ) {
    *tot_w = len_w;
    return 0;
  }

  vec_u = c3_malloc(sizeof(h2o_iovec_t) * len_w);
  len_w = 0;

  while( bod_u ) {
    vec_u[len_w] = h2o_iovec_init(bod_u->hun_y, bod_u->len_w);
    len_w++;
    bod_u = bod_u->nex_u;
  }

  *tot_w = len_w;

  return vec_u;
}

// XX deduplicate with _http_heds_free
/* _cttp_heds_free(): free header linked list
*/
static void
_cttp_heds_free(u3_hhed* hed_u)
{
  while ( hed_u ) {
    u3_hhed* nex_u = hed_u->nex_u;

    free(hed_u->nam_c);
    free(hed_u->val_c);
    free(hed_u);
    hed_u = nex_u;
  }
}

// XX deduplicate with _http_hed_new
/* _cttp_hed_new(): create u3_hhed from nam/val cords
*/
static u3_hhed*
_cttp_hed_new(u3_atom nam, u3_atom val)
{
  c3_w     nam_w = u3r_met(3, nam);
  c3_w     val_w = u3r_met(3, val);
  u3_hhed* hed_u = c3_malloc(sizeof(*hed_u));

  hed_u->nam_c = c3_malloc(1 + nam_w);
  hed_u->val_c = c3_malloc(1 + val_w);
  hed_u->nam_c[nam_w] = 0;
  hed_u->val_c[val_w] = 0;
  hed_u->nex_u = 0;
  hed_u->nam_w = nam_w;
  hed_u->val_w = val_w;

  u3r_bytes(0, nam_w, (c3_y*)hed_u->nam_c, nam);
  u3r_bytes(0, val_w, (c3_y*)hed_u->val_c, val);

  return hed_u;
}

// XX vv similar to _http_heds_from_noun
/* _cttp_heds_math(): create headers from +math
*/
static u3_hhed*
_cttp_heds_math(u3_noun mah)
{
  u3_noun hed = u3kdi_tap(mah);
  u3_noun deh = hed;

  u3_hhed* hed_u = 0;

  while ( u3_nul != hed ) {
    u3_noun nam = u3h(u3h(hed));
    u3_noun lit = u3t(u3h(hed));

    while ( u3_nul != lit ) {
      u3_hhed* nex_u = _cttp_hed_new(nam, u3h(lit));
      nex_u->nex_u = hed_u;

      hed_u = nex_u;
      lit = u3t(lit);
    }

    hed = u3t(hed);
  }

  u3z(deh);
  return hed_u;
}

// XX deduplicate with _http_heds_to_noun
/* _cttp_heds_to_noun(): convert h2o_header_t to (list (pair @t @t))
*/
static u3_noun
_cttp_heds_to_noun(h2o_header_t* hed_u, c3_d hed_d)
{
  u3_noun hed = u3_nul;
  c3_d dex_d  = hed_d;

  h2o_header_t deh_u;

  while ( 0 < dex_d ) {
    deh_u = hed_u[--dex_d];
    hed = u3nc(u3nc(_cttp_vec_to_atom(*deh_u.name),
                    _cttp_vec_to_atom(deh_u.value)), hed);
  }

  return hed;
}

/* _cttp_cres_free(): free a u3_cres.
*/
static void
_cttp_cres_free(u3_cres* res_u)
{
  _cttp_bods_free(res_u->bod_u);
  free(res_u);
}

/* _cttp_cres_new(): create a response
*/
static void
_cttp_cres_new(u3_creq* ceq_u, c3_w sas_w)
{
  ceq_u->res_u = c3_calloc(sizeof(*ceq_u->res_u));
  ceq_u->res_u->sas_w = sas_w;
}

/* _cttp_cres_fire_body(): attach response body buffer
*/
static void
_cttp_cres_fire_body(u3_cres* res_u, u3_hbod* bod_u)
{
  c3_assert(!bod_u->nex_u);

  if ( !(res_u->bod_u) ) {
    res_u->bod_u = bod_u;
  } else {
    res_u->bod_u->nex_u = bod_u;
  }
}

/* _cttp_mcut_char(): measure/cut character.
*/
static c3_w
_cttp_mcut_char(c3_c* buf_c, c3_w len_w, c3_c chr_c)
{
  if ( buf_c ) {
    buf_c[len_w] = chr_c;
  }
  return len_w + 1;
}

/* _cttp_mcut_cord(): measure/cut cord.
*/
static c3_w
_cttp_mcut_cord(c3_c* buf_c, c3_w len_w, u3_noun san)
{
  c3_w ten_w = u3r_met(3, san);

  if ( buf_c ) {
    u3r_bytes(0, ten_w, (c3_y *)(buf_c + len_w), san);
  }
  u3z(san);
  return (len_w + ten_w);
}

/* _cttp_mcut_path(): measure/cut cord list.
*/
static c3_w
_cttp_mcut_path(c3_c* buf_c, c3_w len_w, c3_c sep_c, u3_noun pax)
{
  u3_noun axp = pax;

  while ( u3_nul != axp ) {
    u3_noun h_axp = u3h(axp);

    len_w = _cttp_mcut_cord(buf_c, len_w, u3k(h_axp));
    axp = u3t(axp);

    if ( u3_nul != axp ) {
      len_w = _cttp_mcut_char(buf_c, len_w, sep_c);
    }
  }
  u3z(pax);
  return len_w;
}

/* _cttp_mcut_host(): measure/cut host.
*/
static c3_w
_cttp_mcut_host(c3_c* buf_c, c3_w len_w, u3_noun hot)
{
  len_w = _cttp_mcut_path(buf_c, len_w, '.', u3kb_flop(u3k(hot)));
  u3z(hot);
  return len_w;
}

/* _cttp_mcut_pork(): measure/cut path/extension.
*/
static c3_w
_cttp_mcut_pork(c3_c* buf_c, c3_w len_w, u3_noun pok)
{
  u3_noun h_pok = u3h(pok);
  u3_noun t_pok = u3t(pok);

  len_w = _cttp_mcut_path(buf_c, len_w, '/', u3k(t_pok));
  if ( u3_nul != h_pok ) {
    len_w = _cttp_mcut_char(buf_c, len_w, '.');
    len_w = _cttp_mcut_cord(buf_c, len_w, u3k(u3t(h_pok)));
  }
  u3z(pok);
  return len_w;
}

/* _cttp_mcut_quay(): measure/cut query.
*/
static c3_w
_cttp_mcut_quay(c3_c* buf_c, c3_w len_w, u3_noun quy)
{
  if ( u3_nul == quy ) {
    return len_w;
  }
  else {
    u3_noun i_quy = u3h(quy);
    u3_noun pi_quy = u3h(i_quy);
    u3_noun qi_quy = u3t(i_quy);
    u3_noun t_quy = u3t(quy);

    len_w = _cttp_mcut_char(buf_c, len_w, '&');
    len_w = _cttp_mcut_cord(buf_c, len_w, u3k(pi_quy));
    len_w = _cttp_mcut_char(buf_c, len_w, '=');
    len_w = _cttp_mcut_cord(buf_c, len_w, u3k(qi_quy));

    len_w = _cttp_mcut_quay(buf_c, len_w, u3k(t_quy));
  }
  u3z(quy);
  return len_w;
}

/* _cttp_mcut_url(): measure/cut purl, producing relative URL.
*/
static c3_w
_cttp_mcut_url(c3_c* buf_c, c3_w len_w, u3_noun pul)
{
  u3_noun q_pul = u3h(u3t(pul));
  u3_noun r_pul = u3t(u3t(pul));

  len_w = _cttp_mcut_char(buf_c, len_w, '/');
  len_w = _cttp_mcut_pork(buf_c, len_w, u3k(q_pul));

  if ( u3_nul != r_pul ) {
    len_w = _cttp_mcut_char(buf_c, len_w, '?');
    len_w = _cttp_mcut_quay(buf_c, len_w, u3k(r_pul));
  }
  u3z(pul);
  return len_w;
}

/* _cttp_creq_port(): stringify port
*/
static c3_c*
_cttp_creq_port(c3_s por_s)
{
  c3_c* por_c = c3_malloc(8);
  snprintf(por_c, 7, "%d", 0xffff & por_s);
  return por_c;
}

/* _cttp_creq_url(): construct url from noun.
*/
static c3_c*
_cttp_creq_url(u3_noun pul)
{
  c3_w  len_w = _cttp_mcut_url(0, 0, u3k(pul));
  c3_c* url_c = c3_malloc(1 + len_w);

  _cttp_mcut_url(url_c, 0, pul);
  url_c[len_w] = 0;

  return url_c;
}

/* _cttp_creq_host(): construct host from noun.
*/
static c3_c*
_cttp_creq_host(u3_noun hot)
{
  c3_w  len_w = _cttp_mcut_host(0, 0, u3k(hot));
  c3_c* hot_c = c3_malloc(1 + len_w);

  _cttp_mcut_host(hot_c, 0, hot);
  hot_c[len_w] = 0;

  return hot_c;
}

/* _cttp_creq_ip(): stringify ip
*/
static c3_c*
_cttp_creq_ip(c3_w ipf_w)
{
  c3_c* ipf_c = c3_malloc(17);
  snprintf(ipf_c, 16, "%d.%d.%d.%d", (ipf_w >> 24),
                                     ((ipf_w >> 16) & 255),
                                     ((ipf_w >> 8) & 255),
                                     (ipf_w & 255));
  return ipf_c;
}

/* _cttp_creq_find(): find a request by number in the client
*/
static u3_creq*
_cttp_creq_find(c3_l num_l)
{
  u3_creq* ceq_u = u3_Host.ctp_u.ceq_u;

  //  XX glories of linear search
  //
  while ( ceq_u ) {
    if ( num_l == ceq_u->num_l ) {
      return ceq_u;
    }
    ceq_u = ceq_u->nex_u;
  }
  return 0;
}

/* _cttp_creq_link(): link request to client
*/
static void
_cttp_creq_link(u3_creq* ceq_u)
{
  ceq_u->nex_u = u3_Host.ctp_u.ceq_u;

  if ( 0 != ceq_u->nex_u ) {
    ceq_u->nex_u->pre_u = ceq_u;
  }
  u3_Host.ctp_u.ceq_u = ceq_u;
}

/* _cttp_creq_unlink(): unlink request from client
*/
static void
_cttp_creq_unlink(u3_creq* ceq_u)
{
  if ( ceq_u->pre_u ) {
    ceq_u->pre_u->nex_u = ceq_u->nex_u;

    if ( 0 != ceq_u->nex_u ) {
      ceq_u->nex_u->pre_u = ceq_u->pre_u;
    }
  }
  else {
    u3_Host.ctp_u.ceq_u = ceq_u->nex_u;

    if ( 0 != ceq_u->nex_u ) {
      ceq_u->nex_u->pre_u = 0;
    }
  }
}

/* _cttp_creq_free(): free a u3_creq.
*/
static void
_cttp_creq_free(u3_creq* ceq_u)
{
  uL(fprintf(uH, "free ceq_u\n"));
  _cttp_creq_unlink(ceq_u);

  _cttp_heds_free(ceq_u->hed_u);
  free(ceq_u->bod_u);

  if ( ceq_u->res_u ) {
    _cttp_cres_free(ceq_u->res_u);
  }

  free(ceq_u->hot_c);
  free(ceq_u->por_c);
  free(ceq_u->url_c);

  free(ceq_u->vec_u);
  free(ceq_u);
  uL(fprintf(uH, "end of free ceq_u\n"));
}

/* _cttp_creq_new(): create a request from a +hiss noun
*/
static u3_creq*
_cttp_creq_new(c3_l num_l, u3_noun hes)
{
  u3_creq* ceq_u = c3_calloc(sizeof(*ceq_u));

  u3_noun pul = u3h(hes);      // +purl
  u3_noun hat = u3h(pul);      // +hart
  u3_noun sec = u3h(hat);
  u3_noun por = u3h(u3t(hat));
  u3_noun hot = u3t(u3t(hat)); // +host
  u3_noun moh = u3t(hes);      // +moth
  u3_noun met = u3h(moh);      // +meth
  u3_noun mah = u3h(u3t(moh)); // +math
  u3_noun bod = u3t(u3t(moh));

  ceq_u->sat_e = u3_csat_init;
  ceq_u->num_l = num_l;
  ceq_u->sec   = sec;

  if ( c3y == u3h(hot) ) {
    ceq_u->hot_c = _cttp_creq_host(u3k(u3t(hot)));
  } else {
    ceq_u->ipf_w = u3r_word(0, u3t(hot));
    ceq_u->ipf_c = _cttp_creq_ip(ceq_u->ipf_w);
  }

  if ( u3_nul != por ) {
    ceq_u->por_s = u3t(por);
    ceq_u->por_c = _cttp_creq_port(ceq_u->por_s);
  }

  ceq_u->met_m = met;
  ceq_u->url_c = _cttp_creq_url(u3k(pul));
  ceq_u->hed_u = _cttp_heds_math(u3k(mah));
  h2o_mem_init_pool(&(ceq_u->pol_u));

  if ( u3_nul != bod ) {
    ceq_u->bod_u = _cttp_bod_from_octs(u3k(u3t(bod)));
  }

  _cttp_creq_link(ceq_u);

  u3z(hes);
  return ceq_u;
}

/* _cttp_creq_quit(): cancel a u3_creq
*/
static void
_cttp_creq_quit(u3_creq* ceq_u)
{
  if ( u3_csat_addr == ceq_u->sat_e ) {
    ceq_u->sat_e = u3_csat_quit;
    return;  // wait to be called again on address resolution
  }

  uL(fprintf(uH, "creq_quit\n"));
  _cttp_creq_free(ceq_u);
}

/* _cttp_httr(): dispatch http response to %eyre
*/
static void
_cttp_httr(c3_l num_l, c3_w sas_w, u3_noun mes, u3_noun uct)
{
  u3_noun htr = u3nt(sas_w, mes, uct);
  u3_noun pox = u3nt(u3_blip, c3__http, u3_nul);

  uL(fprintf(uH, "cttp httr"));
  u3v_plan(pox, u3nt(c3__they, num_l, htr));
  uL(fprintf(uH, "done with u3v_plan\n"));
}

/* _cttp_creq_quit(): dispatch error response
*/
static void
_cttp_creq_fail(u3_creq* ceq_u, const c3_c* err_c)
{
  // XX anything other than a 504?
  c3_w cod_w = 504;

  uL(fprintf(uH, "http: fail (%d, %d): %s\r\n", ceq_u->num_l, cod_w, err_c));

  // XX include err_c as response body?
  _cttp_httr(ceq_u->num_l, cod_w, u3_nul, u3_nul);
  _cttp_creq_free(ceq_u);
}

/* _cttp_creq_quit(): dispatch response
*/
static void
_cttp_creq_respond(u3_creq* ceq_u)
{
  u3_cres* res_u = ceq_u->res_u;

  uL(fprintf(uH, "creq_respond"));
  _cttp_httr(ceq_u->num_l, res_u->sas_w, res_u->hed,
             ( !res_u->bod_u ) ? u3_nul :
             u3nc(u3_nul, _cttp_bods_to_octs(res_u->bod_u)));

  _cttp_creq_free(ceq_u);
}

// XX research: may be called with closed client?
/* _cttp_creq_on_body(): cb invoked by h2o upon receiving a response body
*/
static c3_i
_cttp_creq_on_body(h2o_httpclient_t* cli_u, const c3_c* err_c)
{
  u3_creq* ceq_u = (u3_creq *)cli_u->data;
  uL(fprintf(uH, "on_body\n"));

  if ( 0 != err_c && h2o_httpclient_error_is_eos != err_c ) {
    uL(fprintf(uH, "creq_fail\n"));
    _cttp_creq_fail(ceq_u, err_c);
    return -1;
  }

  h2o_buffer_t* buf_u = *cli_u->buf;

  if ( buf_u->size ) {
    uL(fprintf(uH, "buf_u has size"));
    _cttp_cres_fire_body(ceq_u->res_u,
                         _cttp_bod_new(buf_u->size, buf_u->bytes));
    h2o_buffer_consume(cli_u->buf, buf_u->size);
  }

  if ( h2o_httpclient_error_is_eos == err_c ) {
    uL(fprintf(uH, "eos now respond"));
    _cttp_creq_respond(ceq_u);
  }

  return 0;
}

/* _cttp_creq_on_head(): cb invoked by h2o upon receiving response headers
*/
static h2o_httpclient_body_cb
_cttp_creq_on_head(h2o_httpclient_t* cli_u, const c3_c* err_c, c3_i ver_i,
                   c3_i sas_i, h2o_iovec_t sas_u, h2o_header_t* hed_u,
                   size_t hed_t, c3_i len_i)
{
  u3_creq* ceq_u = (u3_creq *)cli_u->data;

  uL(fprintf(uH, "on_head\n"));
  if ( 0 != err_c && h2o_httpclient_error_is_eos != err_c ) {
    _cttp_creq_fail(ceq_u, err_c);
    return 0;
  }

  _cttp_cres_new(ceq_u, (c3_w)sas_i);
  ceq_u->res_u->hed = _cttp_heds_to_noun(hed_u, hed_t);

  if ( h2o_httpclient_error_is_eos == err_c ) {
    _cttp_creq_respond(ceq_u);
    return 0;
  }

  return _cttp_creq_on_body;
}

/* _cttp_creq_on_proceed(): cb invoked by h2o while proceeding with a request
*/
static void
_cttp_creq_on_proceed(h2o_httpclient_t *cli_u, size_t written, 
                      int is_end_stream)
{
  uL(fprintf(uH, "on_proceed\n"));
  u3_creq* ceq_u = (u3_creq *)cli_u->data;

  if (ceq_u->cbs_u > 0) {
      struct st_timeout_ctx *tctx;
      tctx = h2o_mem_alloc(sizeof(*tctx));
      memset(tctx, 0, sizeof(*tctx));
      tctx->client = cli_u;
      tctx->_timeout.cb = timeout_cb;
      h2o_timer_link(cli_u->ctx->loop, 100, &tctx->_timeout);
  }
}

int fill_body(h2o_iovec_t *reqbuf, u3_creq* ceq_u)
{
  if (ceq_u->cbs_u > 0) {
    memcpy(reqbuf, &(ceq_u->iov_u), sizeof(*reqbuf));
    
    if (ceq_u->iov_u.len < ceq_u->cbs_u) {
      reqbuf->len = ceq_u->iov_u.len;
    } else {
      reqbuf->len = ceq_u->cbs_u;
    }
    ceq_u->cbs_u -= reqbuf->len;
    return 0;
  } else {
    *reqbuf = h2o_iovec_init(NULL, 0);
    return 1;
  }
}

static void timeout_cb(h2o_timer_t *entry)
{
    uL(fprintf(uH, "timeout cb\n"));
    static h2o_iovec_t reqbuf;
    struct st_timeout_ctx *tctx = H2O_STRUCT_FROM_MEMBER(struct st_timeout_ctx, _timeout, entry);

    u3_creq* ceq_u = (u3_creq *)tctx->client->data;

    uL(fprintf(uH, "fill body\n"));
    fill_body(&reqbuf, ceq_u);
    h2o_timer_unlink(&tctx->_timeout);
    tctx->client->write_req(tctx->client, reqbuf, ceq_u->cbs_u <= 0);

    free(tctx);
    return;
}

/* _cttp_creq_on_connect(): cb invoked by h2o upon successful connection
*/
static h2o_httpclient_head_cb
_cttp_creq_on_connect(h2o_httpclient_t *cli_u, const c3_c *err_c,
                      h2o_iovec_t *_method, h2o_url_t *url,
                      const h2o_header_t **headers,
                      size_t *num_headers,
                      h2o_iovec_t *body,
                      h2o_httpclient_proceed_req_cb *proceed_req_cb,
                      h2o_httpclient_properties_t *props,
                      h2o_url_t *origin)
{
  u3_creq* ceq_u = (u3_creq *)cli_u->data;
  uL(fprintf(uH, "on_connect\n"));

  if ( 0 != err_c ) {
    _cttp_creq_fail(ceq_u, err_c);
    return 0;
  }

  char *met_m = _cttp_met_to_char(ceq_u->met_m);
  *_method = h2o_iovec_init(met_m, strlen(met_m));

  *url = _cttp_ceq_to_h2o_url(ceq_u);
  *headers = NULL;
  *num_headers = 0;
  *body = h2o_iovec_init(NULL, 0);

  ceq_u->vec_u = _cttp_bods_to_vec(ceq_u->bod_u, &(ceq_u->bsz_u));
  ceq_u->cbs_u = ceq_u->bsz_u;

  if (ceq_u->cbs_u > 0) {
    ceq_u->iov_u.base = h2o_mem_alloc(8192);
    ceq_u->iov_u.len = 8192;

    *body = *(ceq_u->vec_u);
    u3_hhed* hed_u = ceq_u->hed_u;
    h2o_headers_t headers_vec = (h2o_headers_t){NULL};

    c3_c* hos_c = _cttp_ceq_to_host_hed(ceq_u);
    h2o_add_header(&(ceq_u->pol_u), &headers_vec, H2O_TOKEN_HOST,
                    NULL, hos_c, strlen(hos_c));
    free(hos_c);

    c3_c *len_c = c3_calloc(33);
    c3_w len_w = snprintf(len_c, 33, "%u", ceq_u->bod_u->len_w);

    h2o_add_header(&(ceq_u->pol_u), &headers_vec, H2O_TOKEN_CONTENT_LENGTH, 
                    NULL, len_c, len_w);
    free(len_c);

    while (hed_u != NULL) {
      h2o_add_header_by_str(&(ceq_u->pol_u), &headers_vec, hed_u->nam_c,
                             strlen(hed_u->nam_c), 1, hed_u->nam_c, hed_u->val_c, 
                             strlen(hed_u->val_c));
      *num_headers = *num_headers + 1;
      hed_u = hed_u->nex_u;
    }

    *headers = headers_vec.entries;
    *proceed_req_cb = _cttp_creq_on_proceed;
  }

  return _cttp_creq_on_head;
}

/* _cttp_creq_connect(): establish connection
*/
static void
_cttp_creq_connect(u3_creq* ceq_u)
{
  c3_assert(u3_csat_ripe == ceq_u->sat_e);
  c3_assert(ceq_u->ipf_c);

  h2o_url_t url = _cttp_ceq_to_h2o_url(ceq_u);

  h2o_httpclient_connect(NULL, &(ceq_u->pol_u), ceq_u, u3_Host.ctp_u.ctx_u,
                          u3_Host.ctp_u.con_u, &url, _cttp_creq_on_connect);
  
  // set hostname for TLS handshake
  /*
   * TODO: fix TLS
   * if ( ceq_u->hot_c && c3y == ceq_u->sec ) {
    c3_w len_w  = 1 + strlen(ceq_u->hot_c);
    c3_c* hot_c = c3_malloc(len_w);
    strncpy(hot_c, ceq_u->hot_c, len_w);

    free(ceq_u->sok_u->_ssl_ctx->server_name);
    ceq_u->sok_u->_ssl_ctx->server_name = hot_c;
  }*/
}

/* _cttp_creq_resolve_cb(): cb upon IP address resolution
*/
static void
_cttp_creq_resolve_cb(uv_getaddrinfo_t* adr_u,
                      c3_i              sas_i,
                      struct addrinfo*  aif_u)
{
  u3_creq* ceq_u = adr_u->data;

  if ( u3_csat_quit == ceq_u->sat_e ) {
    _cttp_creq_quit(ceq_u);
  }
  else if ( 0 != sas_i ) {
    _cttp_creq_fail(ceq_u, uv_strerror(sas_i));
  }
  else {
    // XX traverse struct a la _ames_czar_cb
    ceq_u->ipf_w = ntohl(((struct sockaddr_in *)aif_u->ai_addr)->sin_addr.s_addr);
    ceq_u->ipf_c = _cttp_creq_ip(ceq_u->ipf_w);

    ceq_u->sat_e = u3_csat_ripe;
    _cttp_creq_connect(ceq_u);
  }

  free(adr_u);
  uv_freeaddrinfo(aif_u);
}

/* _cttp_creq_resolve(): resolve hostname to IP address
*/
static void
_cttp_creq_resolve(u3_creq* ceq_u)
{
  c3_assert(u3_csat_addr == ceq_u->sat_e);
  c3_assert(ceq_u->hot_c);

  uv_getaddrinfo_t* adr_u = c3_malloc(sizeof(*adr_u));
  adr_u->data = ceq_u;

  struct addrinfo hin_u;
  memset(&hin_u, 0, sizeof(struct addrinfo));

  hin_u.ai_family = PF_INET;
  hin_u.ai_socktype = SOCK_STREAM;
  hin_u.ai_protocol = IPPROTO_TCP;

  // XX is this necessary?
  c3_c* por_c = ceq_u->por_c ? ceq_u->por_c :
                ( c3y == ceq_u->sec ) ? "443" : "80";

  c3_i sas_i;

  if ( 0 != (sas_i = uv_getaddrinfo(u3L, adr_u, _cttp_creq_resolve_cb,
                                         ceq_u->hot_c, por_c, &hin_u)) ) {
    uL(fprintf(uH, "fail in res\n"));

    _cttp_creq_fail(ceq_u, uv_strerror(sas_i));
  }
}

/* _cttp_creq_start(): start a request
*/
static void
_cttp_creq_start(u3_creq* ceq_u)
{
  if ( ceq_u->ipf_c ) {
    ceq_u->sat_e = u3_csat_ripe;
    uL(fprintf(uH, "conn\n"));
    _cttp_creq_connect(ceq_u);
  } else {
    uL(fprintf(uH, "res\n"));
    ceq_u->sat_e = u3_csat_addr;
    _cttp_creq_resolve(ceq_u);
  }
}

/* _cttp_init_tls: initialize OpenSSL context
*/
static SSL_CTX*
_cttp_init_tls(uv_buf_t key_u, uv_buf_t cer_u)
{
  // XX require 1.1.0 and use TLS_client_method()
  SSL_CTX* tls_u = SSL_CTX_new(SSLv23_client_method());
  // XX use SSL_CTX_set_max_proto_version() and SSL_CTX_set_min_proto_version()
  SSL_CTX_set_options(tls_u, SSL_OP_NO_SSLv2 |
                             SSL_OP_NO_SSLv3 |
                             // SSL_OP_NO_TLSv1 | // XX test
                             SSL_OP_NO_COMPRESSION);

  SSL_CTX_set_verify(tls_u, SSL_VERIFY_PEER, 0);
  SSL_CTX_set_default_verify_paths(tls_u);
  SSL_CTX_set_session_cache_mode(tls_u, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_cipher_list(tls_u,
                          "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:"
                          "ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:"
                          "RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS");

  if (key_u.len == 0 && cer_u.len == 0) {
    return tls_u;
  }

  {
    BIO* bio_u = BIO_new_mem_buf(key_u.base, key_u.len);
    EVP_PKEY* pky_u = PEM_read_bio_PrivateKey(bio_u, 0, 0, 0);
    c3_i sas_i = SSL_CTX_use_PrivateKey(tls_u, pky_u);

    EVP_PKEY_free(pky_u);
    BIO_free(bio_u);

    if( 0 == sas_i ) {
      uL(fprintf(uH, "cttp: load private key failed:\n"));
      ERR_print_errors_fp(uH);
      uL(1);

      SSL_CTX_free(tls_u);

      return 0;
    }
  }

  {
    BIO* bio_u = BIO_new_mem_buf(cer_u.base, cer_u.len);
    X509* xer_u = PEM_read_bio_X509_AUX(bio_u, 0, 0, 0);
    c3_i sas_i = SSL_CTX_use_certificate(tls_u, xer_u);

    X509_free(xer_u);

    if( 0 == sas_i ) {
      uL(fprintf(uH, "cttp: load certificate failed:\n"));
      ERR_print_errors_fp(uH);
      uL(1);

      BIO_free(bio_u);
      SSL_CTX_free(tls_u);

      return 0;
    }

    // get any additional CA certs, ignoring errors
    while ( 0 != (xer_u = PEM_read_bio_X509(bio_u, 0, 0, 0)) ) {
      // XX require 1.0.2 or newer and use SSL_CTX_add0_chain_cert
      SSL_CTX_add_extra_chain_cert(tls_u, xer_u);
    }

    BIO_free(bio_u);
  }

  return tls_u;
}

/* _cttp_init_h2o: initialize h2o client ctx and timeout
*/
static h2o_httpclient_ctx_t*
_cttp_init_h2o()
{
  c3_d tim_u = 300 * 1000;

  h2o_httpclient_ctx_t* ctx_u = c3_calloc(sizeof(*ctx_u));
  ctx_u->max_buffer_size = SIZE_MAX;
  ctx_u->http2.ratio = 1;
  ctx_u->loop = u3L;
  ctx_u->io_timeout = tim_u;
  ctx_u->connect_timeout = tim_u;
  ctx_u->first_byte_timeout = tim_u;

  return ctx_u;
};

static h2o_socketpool_t*
_cttp_init_h2o_socketpool(h2o_httpclient_ctx_t* ctx_u)
{
  h2o_socketpool_t* sok_u = c3_calloc(sizeof(*sok_u));
  h2o_socketpool_init_global(sok_u, 10);
  h2o_socketpool_set_timeout(sok_u, 30 * 1000);
  h2o_socketpool_register_loop(sok_u, ctx_u->loop);

  return sok_u;
};

static h2o_httpclient_connection_pool_t*
_cttp_init_h2o_connectionpool(h2o_socketpool_t* sok_u)
{
  h2o_httpclient_connection_pool_t* con_u = c3_calloc(sizeof(*con_u));
  h2o_httpclient_connection_pool_init(con_u, sok_u);
  return con_u;
}
/* u3_cttp_ef_thus(): send %thus effect (outgoing request) to cttp.
*/
void
u3_cttp_ef_thus(c3_l    num_l,
                u3_noun cuq)
{
  u3_creq* ceq_u;

  uL(fprintf(uH, "received thus\n"));
  if ( u3_nul == cuq ) {
    ceq_u =_cttp_creq_find(num_l);

    if ( ceq_u ) {
      _cttp_creq_quit(ceq_u);
    }
  }
  else {
    ceq_u = _cttp_creq_new(num_l, u3k(u3t(cuq)));
    _cttp_creq_start(ceq_u);
  }
  u3z(cuq);
}

/* u3_cttp_ef_cert(): send %cert effect to cttp.
*/
void
u3_cttp_ef_cert(u3_noun crt)
{
  u3_ccrt* crt_u = c3_malloc(sizeof(*crt_u));

  if (( u3_nul == crt ) || !( c3y == u3du(crt) &&
                               c3y == u3du(u3t(crt)) &&
                               u3_nul == u3h(crt) ) ) {
    uL(fprintf(uH, "cttp: cert: invalid card\n"));
    u3z(crt);
    return;
  }
  
  if ( u3_nul != crt ) {
    u3_noun key = u3h(u3t(crt));
    u3_noun cer = u3t(u3t(crt));

    crt_u->key_u = _cttp_wain_to_buf(u3k(key));
    crt_u->cer_u = _cttp_wain_to_buf(u3k(cer));
  } else {
    crt_u->key_u = uv_buf_init(0, 0);
    crt_u->cer_u = uv_buf_init(0, 0);
  }

  u3z(crt);
  _cttp_cert_free();

  SSL_CTX_free(u3_Host.ctp_u.tls_u);
  u3_Host.crt_u.key_u = crt_u->key_u;
  u3_Host.crt_u.cer_u = crt_u->cer_u;
  u3_Host.ctp_u.tls_u = _cttp_init_tls(crt_u->key_u, crt_u->cer_u);
  h2o_socketpool_set_ssl_ctx(u3_Host.ctp_u.sok_u, u3_Host.ctp_u.tls_u);
}

static uv_buf_t
_cttp_wain_to_buf(u3_noun wan)
{
  c3_w len_w = _cttp_mcut_path(0, 0, (c3_c)10, u3k(wan));
  c3_c* buf_c = c3_malloc(1 + len_w);

  _cttp_mcut_path(buf_c, 0, (c3_c)10, wan);
  buf_c[len_w] = 0;

  return uv_buf_init(buf_c, len_w);
}

static void
_cttp_cert_free(void)
{
  u3_ccrt* crt_u = &u3_Host.crt_u;
  
  if ( 0 == crt_u ) {
    return;
  }

  if ( 0 != crt_u->key_u.base) {
    free(crt_u->key_u.base);
  }

  if ( 0 != crt_u->cer_u.base) {
    free(crt_u->cer_u.base);
  }
}

/* u3_cttp_io_init(): initialize http client I/O.
*/
void
u3_cttp_io_init()
{
  u3_ccrt* crt_u = &u3_Host.crt_u;
  c3_assert( 0 != crt_u );

  uL(fprintf(uH, "cttp: io init\n"));

  u3_Host.ctp_u.tls_u = _cttp_init_tls(crt_u->key_u, crt_u->cer_u);
  u3_Host.ctp_u.ctx_u = _cttp_init_h2o();
  u3_Host.ctp_u.sok_u = _cttp_init_h2o_socketpool(u3_Host.ctp_u.ctx_u);
  u3_Host.ctp_u.con_u = _cttp_init_h2o_connectionpool(u3_Host.ctp_u.sok_u);
  h2o_socketpool_set_ssl_ctx(u3_Host.ctp_u.sok_u, u3_Host.ctp_u.tls_u);
  u3_Host.ctp_u.ceq_u = 0;
}

/* u3_cttp_io_exit(): shut down cttp.
*/
void
u3_cttp_io_exit(void)
{
    SSL_CTX_free(u3_Host.ctp_u.tls_u);
    free(u3_Host.ctp_u.ctx_u);
    free(u3_Host.ctp_u.sok_u);
}
