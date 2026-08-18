#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
/**
 * build-canary-pool.mjs — regenerates deploy/canary-pool.js
 *
 * SELECTION RULES for a bootstrap canary. Every host must be:
 *   1. real and long-lived (a dead canary teaches nothing);
 *   2. boring — a probe contacting it must not, by itself, incriminate the
 *      volunteer running the probe;
 *   3. NOT circumvention-adjacent. No Tor, no VPN vendors, no DoH resolvers,
 *      no mirrors of blocked media. A probe list is seizable evidence and must
 *      read as ordinary developer/academic traffic;
 *   4. NOT political, news, adult, or regionally inflammatory;
 *   5. plausibly TCP-reachable from Iran. Note the probe measures TCP and TLS
 *      only, never HTTP content, so sanction-driven HTTP 403s (common for US
 *      hosts) do not matter — only whether the handshake completes.
 *
 * These are BOOTSTRAP candidates. Their in-country reachability is unverified
 * and rule 5 is a judgement, not a measurement, which is exactly why the
 * collector only scores a canary once another slot has independently reached
 * the same host in the same window. See canary-pool.js.
 */
const GROUPS = {
  standards: [
    'iana.org','www.iana.org','ietf.org','www.ietf.org','rfc-editor.org','www.rfc-editor.org',
    'w3.org','www.w3.org','unicode.org','www.unicode.org','iso.org','www.iso.org',
    'itu.int','www.itu.int','icann.org','www.icann.org','ripe.net','www.ripe.net',
    'apnic.net','www.apnic.net','afrinic.net','lacnic.net','iso20022.org','ecma-international.org',
    'khronos.org','www.khronos.org','oasis-open.org','opengroup.org',
  ],
  university: [
    'ethz.ch','epfl.ch','tum.de','uni-heidelberg.de','lmu.de','uni-bonn.de','rwth-aachen.de','kit.edu',
    'tudelft.nl','uu.nl','leidenuniv.nl','rug.nl','ku.dk','dtu.dk','uio.no','ntnu.no',
    'uu.se','kth.se','lu.se','chalmers.se','helsinki.fi','aalto.fi','cuni.cz','muni.cz',
    'uw.edu.pl','agh.edu.pl','elte.hu','bme.hu','unibo.it','polimi.it','unipd.it','uniroma1.it',
    'unimi.it','ucm.es','upm.es','ub.edu','uab.cat','ulisboa.pt','up.pt','sorbonne-universite.fr',
    'univ-lyon1.fr','unistra.fr','ox.ac.uk','cam.ac.uk','ucl.ac.uk','ed.ac.uk','manchester.ac.uk',
    'bristol.ac.uk','tcd.ie','ucd.ie','unimelb.edu.au','sydney.edu.au','anu.edu.au','auckland.ac.nz',
    'utoronto.ca','ubc.ca','mcgill.ca','uwaterloo.ca','nus.edu.sg','ntu.edu.sg','u-tokyo.ac.jp',
    'kyoto-u.ac.jp','titech.ac.jp','kaist.ac.kr','snu.ac.kr','tsinghua.edu.cn','metu.edu.tr',
    'boun.edu.tr','itu.edu.tr','bilkent.edu.tr','ku.edu.tr',
  ],
  foss: [
    'debian.org','www.debian.org','ftp.debian.org','deb.debian.org','ubuntu.com','archlinux.org',
    'fedoraproject.org','opensuse.org','gentoo.org','alpinelinux.org','freebsd.org','openbsd.org',
    'netbsd.org','kernel.org','www.kernel.org','gnu.org','ftp.gnu.org','fsf.org','apache.org',
    'nginx.org','postgresql.org','sqlite.org','python.org','www.python.org','ruby-lang.org',
    'perl.org','php.net','go.dev','rust-lang.org','nodejs.org','llvm.org','cmake.org','git-scm.com',
    'videolan.org','ffmpeg.org','gimp.org','inkscape.org','blender.org','libreoffice.org',
    'documentfoundation.org','kde.org','gnome.org','xfce.org','mozilla.org','openssl.org',
    'openssh.com','curl.se','varnish-cache.org','redis.io','rabbitmq.com',
    'elastic.co','grafana.com','prometheus.io','kubernetes.io','docker.com','ansible.com',
    'terraform.io','vim.org','gnu.org.ua','tug.org','ctan.org','r-project.org','octave.org',
    'scilab.org','sagemath.org','qt.io','gtk.org','freedesktop.org','x.org','wireshark.org',
    'gnupg.org','openwrt.org','raspberrypi.com','arduino.cc',
  ],
  registry: [
    'pypi.org','files.pythonhosted.org','rubygems.org','crates.io','static.crates.io',
    'repo1.maven.org','packagist.org','registry.npmjs.org','cdn.jsdelivr.net','unpkg.com',
    'cdnjs.cloudflare.com','hub.docker.com','registry-1.docker.io','quay.io',
    'mirrors.kernel.org','mirror.leaseweb.com','mirror.hetzner.com','ftp.fau.de',
    'mirror.aarnet.edu.au','ftp.jaist.ac.jp','mirror.yandex.ru','mirrors.tuna.tsinghua.edu.cn',
  ],
  science: [
    'cern.ch','home.cern','esa.int','arxiv.org','doi.org','crossref.org','orcid.org','zenodo.org',
    'ncbi.nlm.nih.gov','who.int','un.org','worldbank.org','imf.org','oecd.org','fao.org',
    'unesco.org','wmo.int','noaa.gov','usgs.gov','copernicus.eu','ecmwf.int','emcwf.int',
    'nature.com','springer.com','sciencedirect.com','ieee.org','acm.org','siam.org','ams.org',
    'aps.org','iop.org','rsc.org',
  ],
  infra: [
    'openstreetmap.org','nominatim.openstreetmap.org','tile.openstreetmap.org','geonames.org',
    'timeanddate.com','worldtimeapi.org','ntppool.org','www.ntp.org','iperf.fr','speedtest.net',
    'ripe.net','stat.ripe.net','bgp.he.net','peeringdb.com','ixpdb.euro-ix.net','de-cix.net',
    'linx.net','ams-ix.net','netnod.se','equinix.com',
  ],
};

const seen = new Set();
const out = [];
for (const [group, hosts] of Object.entries(GROUPS)) {
  for (const h of hosts) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) throw new Error(`malformed host: ${h}`);
    if (seen.has(h)) continue;                 // duplicates collapse silently
    seen.add(h);
    out.push({ h, g: group });
  }
}

// Guard against a circumvention-adjacent or inflammatory host slipping in
// during a later edit. Label-exact for short tokens ('tor' must not reject
// 'utoronto.ca'), substring for the unambiguous multi-character ones.
const BANNED_LABEL = new Set(['tor', 'xray', 'porn', 'xxx', 'warp']);
// 'proxy' and 'vpn' are checked as substrings, not labels: haproxy.org is
// perfectly respectable software, but a censor grepping a seized target list
// does not make that distinction, and the volunteer pays for the ambiguity.
const BANNED_SUBSTRING = ['torproject', 'shadowsocks', 'v2ray', 'psiphon', 'lantern',
  'snowflake', 'telegram', 'whatsapp', 'proxy', 'vpn'];
for (const e of out) {
  for (const label of e.h.split('.')) {
    if (BANNED_LABEL.has(label)) throw new Error(`banned label '${label}' in ${e.h}`);
  }
  for (const s of BANNED_SUBSTRING) {
    if (e.h.includes(s)) throw new Error(`banned substring '${s}' in ${e.h}`);
  }
}

if (out.length < 200) throw new Error(`pool too small: ${out.length}`);

const body = out.map((e) => `  { h: '${e.h}', g: '${e.g}' },`).join('\n');
const header = readFileSync(new URL('./canary-pool.header.js', import.meta.url), 'utf8')
  .replace('__COUNT__', String(out.length));
const file = `${header}\nexport const BUILTIN_CANARY_POOL = [\n${body}\n];\n`;
writeFileSync(new URL('../canary-pool.js', import.meta.url), file);
console.log(`wrote canary-pool.js — ${out.length} unique hosts across ${Object.keys(GROUPS).length} groups`);
