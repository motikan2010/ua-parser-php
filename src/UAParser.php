<?php

namespace Extead\UAParser;

class UAParser
{
    const LIBVERSION = '0.7.14';
    const _EMPTY = '';
    const UNKNOWN = '?';
    const FUNC_TYPE = 'function';
    const UNDEF_TYPE = 'undefined';
    const OBJ_TYPE = 'object';
    const STR_TYPE = 'string';
    const MAJOR = 'major'; // deprecated
    const MODEL = 'model';
    const NAME = 'name';
    const TYPE = 'type';
    const VENDOR = 'vendor';
    const VERSION = 'version';
    const ARCHITECTURE = 'architecture';
    const CONSOLE = 'console';
    const MOBILE = 'mobile';
    const TABLET = 'tablet';
    const SMARTTV = 'smarttv';
    const WEARABLE = 'wearable';
    const EMBEDDED = 'embedded';

    const AMAZON  = 'Amazon';
    const APPLE   = 'Apple';
    const ASUS    = 'ASUS';
    const BLACKBERRY = 'BlackBerry';
    const BROWSER = 'Browser';
    const CHROME  = 'Chrome';
    const EDGE    = 'Edge';
    const FIREFOX = 'Firefox';
    const GOOGLE  = 'Google';
    const HUAWEI  = 'Huawei';
    const LG      = 'LG';
    const MICROSOFT = 'Microsoft';
    const MOTOROLA  = 'Motorola';
    const OPERA   = 'Opera';
    const SAMSUNG = 'Samsung';
    const SONY    = 'Sony';
    const XIAOMI  = 'Xiaomi';
    const ZEBRA   = 'Zebra';

    /**
     * @var null
     */
    private $ua;

    /**
     * @var array
     */
    private $rgxmap = [];

    /**
     * @var array
     */
    private $maps = [

        'browser' => [
            'oldsafari' => [
                'version' => [
                    '1.0' => '/8',
                    '1.2' => '/1',
                    '1.3' => '/3',
                    '2.0' => '/412',
                    '2.0.2' => '/416',
                    '2.0.3' => '/417',
                    '2.0.4' => '/419',
                    '?' => '/'
                ]
            ]
        ],

        'device' => [
            'amazon' => [
                'model' => [
                    'Fire Phone' => ['SD', 'KF']
                ]
            ],
            'sprint' => [
                'model' => [
                    'Evo Shift 4G' => '7373KT'
                ],
                'vendor' => [
                    'HTC' => 'APA',
                    'Sprint' => 'Sprint'
                ]
            ]
        ],

        'os' => [
            'windows' => [
                'version' => [
                    'ME' => '4.90',
                    'NT 3.11' => 'NT3.51',
                    'NT 4.0' => 'NT4.0',
                    '2000' => 'NT 5.0',
                    'XP' => ['NT 5.1', 'NT 5.2'],
                    'Vista' => 'NT 6.0',
                    '7' => 'NT 6.1',
                    '8' => 'NT 6.2',
                    '8.1' => 'NT 6.3',
                    '10' => ['NT 6.4', 'NT 10.0'],
                    'RT' => 'ARM'
                ]
            ]
        ]

    ];

    /**
     * @var Mapper
     */
    private $mapper;

    /**
     * @var Util
     */
    private $util;

    /**
     * UAParser constructor.
     * @param null $uastring
     * @param null $extensions
     */
    public function __construct($uastring = null, $extensions = null)
    {

        $this->mapper = new Mapper();
        $this->util = new Util();

        $this->rgxmap = [
            'browser' => [
                [

                // Presto based
                '/(opera\smini)\/([\w\.-]+)/i',                                       // Opera Mini
                '/(opera\s[mobiletab]+).+version\/([\w\.-]+)/i',                      // Opera Mobi/Tablet
                '/(opera).+version\/([\w\.]+)/i',                                     // Opera > 9.80
                '/(opera)[\/\s]+([\w\.]+)/i'                                          // Opera < 9.80
            ], [self::NAME, self::VERSION], [

                '/(opios)[\/\s]+([\w\.]+)/i'                                          // Opera mini on iphone >= 8.0
            ], [[self::NAME, 'Opera Mini'], self::VERSION], [

                '/\s(opr)\/([\w\.]+)/i'                                               // Opera Webkit
            ], [[self::NAME, 'Opera'], self::VERSION], [

                // Mixed
                '/(kindle)\/([\w\.]+)/i',                                             // Kindle
                '/(lunascape|maxthon|netfront|jasmine|blazer)[\/\s]?([\w\.]+)*/i',
                // Lunascape/Maxthon/Netfront/Jasmine/Blazer

                // Trident based
                '/(avant\s|iemobile|slim|baidu)(?:browser)?[\/\s]?([\w\.]*)/i',
                // Avant/I'EMobile/SlimBrowser/Baidu
                '/(?:ms|\()(ie)\s([\w\.]+)/i',                                        // Internet Explorer

                // Webkit/KHTML based
                '/(rekonq)\/([\w\.]+)*/i',                                            // Rekonq
                '/(chromium|flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser)\/([\w\.-]+)/i'
                // Chromium/Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/I'ridium/PhantomJS/Bowser
            ], [self::NAME, self::VERSION], [

                '/(trident).+rv[:\s]([\w\.]+).+like\sgecko/i'                         // IE11
            ], [[self::NAME, 'IE'], self::VERSION], [

                '/(edge)\/((\d+)?[\w\.]+)/i'                                          // Microsoft Edge
            ], [self::NAME, self::VERSION], [

                '/(yabrowser)\/([\w\.]+)/i'                                           // Yandex
            ], [[self::NAME, 'Yandex'], self::VERSION], [

                '/(puffin)\/([\w\.]+)/i'                                              // Puffin
            ], [[self::NAME, 'Puffin'], self::VERSION], [

                '/((?:[\s\/])uc?\s?browser|(?:juc.+)ucweb)[\/\s]?([\w\.]+)/i'
                // UCBrowser
            ], [[self::NAME, 'UCBrowser'], self::VERSION], [

                '/(comodo_dragon)\/([\w\.]+)/i'                                       // Comodo Dragon
            ], [[self::NAME, '/_/', ' '], self::VERSION], [

                '/(micromessenger)\/([\w\.]+)/i'                                      // WeChat
            ], [[self::NAME, 'WeChat'], self::VERSION], [

                '/(QQ)\/([\d\.]+)/i'                                                  // QQ, aka ShouQ
            ], [self::NAME, self::VERSION], [

                '/m?(qqbrowser)[\/\s]?([\w\.]+)/i'                                    // QQBrowser
            ], [self::NAME, self::VERSION], [

                '/xiaomi\/miuibrowser\/([\w\.]+)/i'                                   // MIUI Browser
            ], [self::VERSION, [self::NAME, 'MIUI Browser']], [

                '/;fbav\/([\w\.]+);/i'                                                // Facebook App for iOS & Android
            ], [self::VERSION, [self::NAME, 'Facebook']], [

                '/(headlesschrome) ([\w\.]+)/i'                                       // Chrome Headless
            ], [self::VERSION, [self::NAME, 'Chrome Headless']], [

                '/\swv\).+(chrome)\/([\w\.]+)/i'                                      // Chrome WebView
            ], [[self::NAME, '/(.+)/', '$1 WebView'], self::VERSION], [

                '/((?:oculus|samsung)browser)\/([\w\.]+)/i'
            ], [[self::NAME, '/(.+(?:g|us))(.+)/', '$1 $2'], self::VERSION], [                // Oculus / Samsung Browser

                '/android.+version\/([\w\.]+)\s+(?:mobile\s?safari|safari)*/i'        // Android Browser
            ], [self::VERSION, [self::NAME, 'Android Browser']], [

                '/(chrome|omniweb|arora|[tizenoka]{5}\s?browser)\/v?([\w\.]+)/i'
                // Chrome/OmniWeb/Arora/Tizen/Nokia
            ], [self::NAME, self::VERSION], [

                '/(dolfin)\/([\w\.]+)/i'                                              // Dolphin
            ], [[self::NAME, 'Dolphin'], self::VERSION], [

                '/((?:android.+)crmo|crios)\/([\w\.]+)/i'                             // Chrome for Android iOS
            ], [[self::NAME, 'Chrome'], self::VERSION], [

                '/(coast)\/([\w\.]+)/i'                                               // Opera Coast
            ], [[self::NAME, 'Opera Coast'], self::VERSION], [

                '/fxios\/([\w\.-]+)/i'                                                // Firefox for iOS
            ], [self::VERSION, [self::NAME, 'Firefox']], [

                '/version\/([\w\.]+).+?mobile\/\w+\s(safari)/i'                       // Mobile Safari
            ], [self::VERSION, [self::NAME, 'Mobile Safari']], [

                '/version\/([\w\.]+).+?(mobile\s?safari|safari)/i'                    // Safari & Safari Mobile
            ], [self::VERSION, self::NAME], [

                '/webkit.+?(mobile\s?safari|safari)(\/[\w\.]+)/i'                     // Safari < 3.0
            ], [self::NAME, [self::VERSION, function ($str, $map) {
                return $this->mapper->str($str, $map);
            }, $this->maps['browser']['oldsafari']['version']]], [

                '/(konqueror)\/([\w\.]+)/i',                                          // Konqueror
                '/(webkit|khtml)\/([\w\.]+)/i'
            ], [self::NAME, self::VERSION], [

                // Gecko based
                '/(navigator|netscape)\/([\w\.-]+)/i'                                 // Netscape
            ], [[self::NAME, 'Netscape'], self::VERSION], [
                '/(swiftfox)/i',                                                      // Swiftfox
                '/(icedragon|iceweasel|camino|chimera|fennec|maemo\sbrowser|minimo|conkeror)[\/\s]?([\w\.\+]+)/i',
                // IceDragon/I'ceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
                '/(firefox|seamonkey|k-meleon|icecat|iceape|firebird|phoenix)\/([\w\.-]+)/i',
                // Firefox/SeaMonkey/K-Meleon/IceCat/I'ceApe/Firebird/Phoenix
                '/(mozilla)\/([\w\.]+).+rv\:.+gecko\/\d+/i',                          // Mozilla

                // Other
                '/(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir)[\/\s]?([\w\.]+)/i',
                // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf/Sleipnir
                '/(links)\s\(([\w\.]+)/i',                                            // Links
                '/(gobrowser)\/?([\w\.]+)*/i',                                        // GoBrowser
                '/(ice\s?browser)\/v?([\w\._]+)/i',                                   // ICE Browser
                '/(mosaic)[\/\s]([\w\.]+)/i'                                          // Mosaic
            ], [self::NAME, self::VERSION]

                /* /////////////////////
                // Media players BEGIN
                ////////////////////////
                , [
                '/(apple(?:coremedia|))\/((\d+)[\w\._]+)/i',                          // Generic Apple CoreMedia
                '/(coremedia) v((\d+)[\w\._]+)/i'
                ], [self::NAME, self::VERSION], [
                '/(aqualung|lyssna|bsplayer)\/((\d+)?[\w\.-]+)/i'                     // Aqualung/Lyssna/BSPlayer
                ], [self::NAME, self::VERSION], [
                '/(ares|ossproxy)\s((\d+)[\w\.-]+)/i'                                 // Ares/OSSProxy
                ], [self::NAME, self::VERSION], [
                '/(audacious|audimusicstream|amarok|bass|core|dalvik|gnomemplayer|music on console|nsplayer|psp-internetradioplayer|videos)\/((\d+)[\w\.-]+)/i',
                                                                                    // Audacious/AudiMusicStream/Amarok/BASS/OpenCORE/Dalvik/GnomeMplayer/MoC
                                                                                    // NSPlayer/PSP-InternetRadioPlayer/Videos
                '/(clementine|music player daemon)\s((\d+)[\w\.-]+)/i',               // Clementine/MPD
                '/(lg player|nexplayer)\s((\d+)[\d\.]+)/i',
                '/player\/(nexplayer|lg player)\s((\d+)[\w\.-]+)/i'                   // NexPlayer/LG Player
                ], [self::NAME, self::VERSION], [
                '/(nexplayer)\s((\d+)[\w\.-]+)/i'                                     // Nexplayer
                ], [self::NAME, self::VERSION], [
                '/(flrp)\/((\d+)[\w\.-]+)/i'                                          // Flip Player
                ], [[self::NAME, 'Flip Player'], self::VERSION], [
                '/(fstream|nativehost|queryseekspider|ia-archiver|facebookexternalhit)/i'
                                                                                    '// FStream/NativeHost/QuerySeekSpider/I'A Archiver/facebookexternalhit
                ], [self::NAME], [
                '/(gstreamer) souphttpsrc (?:\([^\)]+\)){0,1} libsoup\/((\d+)[\w\.-]+)/i'
                                                                                    // Gstreamer
                ], [self::NAME, self::VERSION], [
                '/(htc streaming player)\s[\w_]+\s\/\s((\d+)[\d\.]+)/i',              // HTC Streaming Player
                '/(java|python-urllib|python-requests|wget|libcurl)\/((\d+)[\w\.-_]+)/i',
                                                                                    // Java/urllib/requests/wget/cURL
                '/(lavf)((\d+)[\d\.]+)/i'                                             // Lavf (FFMPEG)
                ], [self::NAME, self::VERSION], [
                '/(htc_one_s)\/((\d+)[\d\.]+)/i'                                      // HTC One S
                ], [[self::NAME, /_/, ' '], self::VERSION], [
                '/(mplayer)(?:\s|\/)(?:(?:sherpya-){0,1}svn)(?:-|\s)(r\d+(?:-\d+[\w\.-]+){0,1})/i'
                                                                                    // MPlayer SVN
                ], [self::NAME, self::VERSION], [
                '/(mplayer)(?:\s|\/|[unkow-]+)((\d+)[\w\.-]+)/i'                      // MPlayer
                ], [self::NAME, self::VERSION], [
                '/(mplayer)/i',                                                       // MPlayer (no other info)
                '/(yourmuze)/i',                                                      // YourMuze
                '/(media player classic|nero showtime)/i'                             // Media Player Classic/Nero ShowTime
                ], [self::NAME], [
                '/(nero (?:home|scout))\/((\d+)[\w\.-]+)/i'                           // Nero Home/Nero Scout
                ], [self::NAME, self::VERSION], [
                '/(nokia\d+)\/((\d+)[\w\.-]+)/i'                                      // Nokia
                ], [self::NAME, self::VERSION], [
                '/\s(songbird)\/((\d+)[\w\.-]+)/i'                                    // Songbird/Philips-Songbird
                ], [self::NAME, self::VERSION], [
                '/(winamp)3 version ((\d+)[\w\.-]+)/i',                               // Winamp
                '/(winamp)\s((\d+)[\w\.-]+)/i',
                '/(winamp)mpeg\/((\d+)[\w\.-]+)/i'
                ], [self::NAME, self::VERSION], [
                '/(ocms-bot|tapinradio|tunein radio|unknown|winamp|inlight radio)/i'  // OCMS-bot/tap in radio/tunein/unknown/winamp (no other info)
                                                                                    // inlight radio
                ], [self::NAME], [
                '/(quicktime|rma|radioapp|radioclientapplication|soundtap|totem|stagefright|streamium)\/((\d+)[\w\.-]+)/i'
                                                                                    // QuickTime/RealMedia/RadioApp/RadioClientApplication/
                                                                                    // SoundTap/Totem/Stagefright/Streamium
                ], [self::NAME, self::VERSION], [
                '/(smp)((\d+)[\d\.]+)/i'                                              // SMP
                ], [self::NAME, self::VERSION], [
                '/(vlc) media player - version ((\d+)[\w\.]+)/i',                     // VLC Videolan
                '/(vlc)\/((\d+)[\w\.-]+)/i',
                '/(xbmc|gvfs|xine|xmms|irapp)\/((\d+)[\w\.-]+)/i,                    // XBMC/gvfs/Xine/XMMS/i'rapp
                '/(foobar2000)\/((\d+)[\d\.]+)/i',                                    // Foobar2000
                '/(itunes)\/((\d+)[\d\.]+)/i'                                         // iTunes
                ], [self::NAME, self::VERSION], [
                '/(wmplayer)\/((\d+)[\w\.-]+)/i',                                     // Windows Media Player
                '/(windows-media-player)\/((\d+)[\w\.-]+)/i'
                ], [[self::NAME, /-/, ' '], self::VERSION], [
                '/windows\/((\d+)[\w\.-]+) upnp\/[\d\.]+ dlnadoc\/[\d\.]+ (home media server)/i'
                                                                                    // Windows Media Server
                ], [self::VERSION, [self::NAME, 'Windows']], [
                '/(com\.riseupradioalarm)\/((\d+)[\d\.]*)/i'                          // RiseUP Radio Alarm
                ], [self::NAME, self::VERSION], [
                '/(rad.io)\s((\d+)[\d\.]+)/i',                                        // Rad.io
                '/(radio.(?:de|at|fr))\s((\d+)[\d\.]+)/i'
                ], [[self::NAME, 'rad.io'], self::VERSION]
                //////////////////////
                // Media players END
                ////////////////////*/

            ],

            'cpu' => [
                [

                '/(?:(amd|x(?:(?:86|64)[-_])?|wow|win)64)[;\)]/i'                       // AMD64 (x64)
            ], [[self::ARCHITECTURE, 'amd64']], [

                '/(ia32(?=;))/i'                                                        // IA32 (quicktime)
            ], [[self::ARCHITECTURE, function ($str) {
                return $this->util->lowerize($str);
            }]], [

                '/((?:i[346]|x)86)[;\)]/i'                                              // IA32 (x86)
            ], [[self::ARCHITECTURE, 'ia32']], [

                '/\b(aarch64|arm(v?8e?l?|_?64))\b/i'                                    // ARM64
            ], [[self::ARCHITECTURE, 'arm64']], [

                '/\b(arm(?:v[67])?ht?n?[fl]p?)\b/i'                                     // ARMHF
            ], [[self::ARCHITECTURE, 'arm64']], [

                // PocketPC mistakenly identified as PowerPC
                '/windows\s(ce|mobile);\sppc;/i'
            ], [[self::ARCHITECTURE, 'arm']], [

                '/((?:ppc|powerpc)(?:64)?)(?: mac|;|\))/i'                              // PowerPC
            ], [[self::ARCHITECTURE, '/ower/', '', function ($str) {
                return $this->util->lowerize($str);
            }]], [

                '/(sun4\w)[;\)]/i'                                                      // SPARC
            ], [[self::ARCHITECTURE, 'sparc']], [

                '/((?:avr32|ia64(?=;))|68k(?=\))|\barm(?=v(?:[1-7]|[5-7]1)l?|;|eabi)|(?=atmel )avr|(?:irix|mips|sparc)(?:64)?\b|pa-risc)/i'
                                                                                        // IA64, 68K, ARM/64, AVR/32, IRIX/64, MIPS/64, SPARC/64, PA-RISC
            ], [[self::ARCHITECTURE, function ($str) {
                return $this->util->lowerize($str);
            }]]
            ],

            'device' => [
                [

                // Samsung
                '/\b(sch-i[89]0\d|shw-m380s|sm-[pt]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i'
            ], [self::MODEL, [self::VENDOR, self::SAMSUNG], [self::TYPE, self::TABLET]], [
                '/\b((?:s[cgp]h|gt|sm)-\w+|galaxy nexus)/i',
                '/samsung[- ]([-\w]+)/i',
                '/sec-(sgh\w+)/i'
            ], [self::MODEL, [self::VENDOR, self::SAMSUNG], [self::TYPE, self::MOBILE]], [

                // Apple
                '/\((ip(?:hone|od)[\w ]*);/i'                                       // iPod/iPhone
            ], [self::MODEL, [self::VENDOR, self::APPLE], [self::TYPE, self::MOBILE]], [
                '/\((ipad);[-\w\),; ]+apple/i',                                     // iPad
                '/applecoremedia\/[\w\.]+ \((ipad)/i',
                '/\b(ipad)\d\d?,\d\d?[;\]].+ios/i',
            ], [self::MODEL, [self::VENDOR, self::APPLE], [self::TYPE, self::TABLET]], [

                // Huawei
                '/\b((?:agr|ags[23]|bah2?|sht?)-a?[lw]\d{2})/i'
            ], [self::MODEL, [self::VENDOR, self::HUAWEI], [self::TYPE, self::TABLET]], [
                '/d\/huawei([\w\s-]+)[;\)]/i',
                '/\b(nexus\s6p|vog-[at]?l\d\d|ane-[at]?l[x\d]\d|eml-a?l\d\da?|lya-[at]?l\d[\dc]|clt-a?l\d\di?|ele-l\d\d)/i',
                '/\b(\w{2,4}-[atu][ln][01259][019])[;\)\s]/i'
            ], [self::MODEL, [self::VENDOR, self::HUAWEI], [self::TYPE, self::MOBILE]], [

                // Xiaomi
                '/\b(poco[\w ]+)(?: bui|\))/i',                             // Xiaomi POCO
                '/\b; (\w+) build\/hm\1/i',                                 // Xiaomi Hongmi 'numeric' models
                '/\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i',                   // Xiaomi Hongmi
                '/\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i',         // Xiaomi Redmi
                '/\b(mi[\s\-_]?(?:a\d|one|one[\s_]plus|note lte)?[\s_]?(?:\d?\w?)[\s_]?(?:plus)?)\sbuild/i' // Xiaomi Mi
            ], [[self::MODEL, '/_/', ' '], [self::VENDOR, self::XIAOMI], [self::TYPE, self::MOBILE]], [
                '/\b(mi[-_ ]?(?:pad)(?:[\w_ ]+))(?: bui|\))/i'              // Mi Pad tablets
            ], [[self::MODEL, '/_/', ' '], [self::VENDOR, self::XIAOMI], [self::TYPE, self::TABLET]], [

                // OPPO
                '/;\s(\w+)\sbuild.+\soppo/i',
                '/\s(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007)\b/i'
            ], [self::MODEL, [self::VENDOR, 'OPPO'], [self::TYPE, self::MOBILE]], [

                // Vivo
                '/\svivo\s(\w+)(?:\sbuild|\))/i',
                '/\s(v[12]\d{3}\w?[at])(?:\sbuild|;)/i'
            ], [self::MODEL, [self::VENDOR, 'Vivo'], [self::TYPE, self::MOBILE]], [

                // Realme
                '/\s(rmx[12]\d{3})(?:\sbuild|;)/i'
            ], [self::MODEL, [self::VENDOR, 'Realme'], [self::TYPE, self::MOBILE]], [

                // Motorol
                '/\s(milestone|droid(?:[2-4x]|\s(?:bionic|x2|pro|razr))?:?(\s4g)?)\b[\w\s]+build\//i',
                '/\smot(?:orola)?[\s-](\w*)/i',
                '/((?:moto[\s\w\(\)]+|xt\d{3,4}|nexus\s6)(?=\sbuild|\)))/i'
            ], [self::MODEL, [self::VENDOR, 'Motorola'], [self::TYPE, self::MOBILE]], [
                '/\s(mz60\d|xoom[\s2]{0,2})\sbuild\//i'
            ], [self::MODEL, [self::VENDOR, 'Motorola'], [self::TYPE, self::TABLET]], [

                // LG
                '/((?=lg)?[vl]k\-?\d{3})\sbuild|\s3\.[\s\w;-]{10}lg?-([06cv9]{3,4})/i'
            ], [self::MODEL, [self::VENDOR, 'LG'], [self::TYPE, self::TABLET]], [
                '/(lm-?f100[nv]?|nexus\s[45])/i',
                '/lg[e;\s\/-]+((?!browser|netcast)\w+)/i',
                '/\blg(\-?[\d\w]+)\sbuild/i'
            ], [self::MODEL, [self::VENDOR, 'LG'], [self::TYPE, self::MOBILE]], [

                // Lenovo
                '/(ideatab[\w\-\s]+)/i',
                '/lenovo\s?(s(?:5000|6000)(?:[\w-]+)|tab(?:[\s\w]+)|yt[\d\w-]{6}|tb[\d\w-]{6})/i'        // Lenovo tablets
            ], [self::MODEL, [self::VENDOR, 'Lenovo'], [self::TYPE, self::TABLET]], [

                // Nokia
                '/(?:maemo|nokia).*(n900|lumia\s\d+)/i',
                '/nokia[\s_-]?([\w\.-]*)/i'
            ], [[self::MODEL, '/_/', ' '], [self::VENDOR, 'Nokia'], [self::TYPE, self::MOBILE]], [

                // Google
                '/droid.+;\s(pixel\sc)[\s)]/i'                                        // Google Pixel C
            ], [self::MODEL, [self::VENDOR, 'Google'], [self::TYPE, self::TABLET]], [
                '/droid.+;\s(pixel[\s\daxl]{0,6})(?:\sbuild|\))/i'                    // Google Pixel
            ], [self::MODEL, [self::VENDOR, 'Google'], [self::TYPE, self::MOBILE]], [

                // Sony
                '/droid.+\s([c-g]\d{4}|so[-l]\w+|xq-a\w[4-7][12])(?=\sbuild\/|\).+chrome\/(?![1-6]{0,1}\d\.))/i'
            ], [self::MODEL, [self::VENDOR, 'Sony'], [self::TYPE, self::MOBILE]], [
                '/sony\stablet\s[ps]\sbuild\//i',
                '/(?:sony)?sgp\w+(?:\sbuild\/|\))/i'
            ], [[self::MODEL, 'Xperia Tablet'], [self::VENDOR, 'Sony'], [self::TYPE, self::TABLET]], [

                // OnePlus
                '/\s(kb2005|in20[12]5|be20[12][59])\b/i',
                '/\ba000(1)\sbuild/i',                                                // OnePlus
                '/\boneplus\s(a\d{4})[\s)]/i'
            ], [self::MODEL, [self::VENDOR, 'OnePlus'], [self::TYPE, self::MOBILE]], [

                // Amazon
                '/(alexa)webm/i',
                '/(kf[a-z]{2}wi)(\sbuild\/|\))/i',                                    // Kindle Fire without Silk
                '/(kf[a-z]+)(\sbuild\/|\)).+silk\//i'                                 // Kindle Fire HD
            ], [self::MODEL, [self::VENDOR, 'Amazon'], [self::TYPE, self::TABLET]], [
                '/(sd|kf)[0349hijorstuw]+(\sbuild\/|\)).+silk\//i'                    // Fire Phone
            ], [[self::MODEL, 'Fire Phone'], [self::VENDOR, 'Amazon'], [self::TYPE, self::MOBILE]], [

                // BlackBerry
                '/\((playbook);[\w\s\),;-]+(rim)/i'                                     // BlackBerry PlayBook
            ], [self::MODEL, self::VENDOR, [self::TYPE, self::TABLET]], [
                '/((?:bb[a-f]|st[hv])100-\d)/i',
                '/\(bb10;\s(\w+)/i'                                                     // BlackBerry 10
            ], [self::MODEL, [self::VENDOR, self::BLACKBERRY], [self::TYPE, self::MOBILE]], [

                // Asus
                '/(?:\b|asus_)(transfo[prime\s]{4,10}\s\w+|eeepc|slider\s\w+|nexus\s7|padfone|p00[cj])/i'
            ], [self::MODEL, [self::VENDOR, self::ASUS], [self::TYPE, self::TABLET]], [
                '/\s(z[es]6[027][01][km][ls]|zenfone\s\d\w?)\b/i'
            ], [self::MODEL, [self::VENDOR, self::ASUS], [self::TYPE, self::MOBILE]], [

                // Asus
                '/(?:\b|asus_)(transfo[prime\s]{4,10}\s\w+|eeepc|slider\s\w+|nexus\s7|padfone|p00[cj])/i'
            ], [self::MODEL, [self::VENDOR, 'ASUS'], [self::TYPE, self::TABLET]], [
                '/\s(z[es]6[027][01][km][ls]|zenfone\s\d\w?)\b/i'
            ], [self::MODEL, [self::VENDOR, 'ASUS'], [self::TYPE, self::MOBILE]], [

                // HTC
                '/(nexus\s9)/i'                                                       // HTC Nexus 9
            ], [self::MODEL, [self::VENDOR, 'HTC'], [self::TYPE, self::TABLET]], [
                '/(htc)[;_\s-]{1,2}([\w\s]+(?=\)|\sbuild)|\w+)/i',                    // HTC

                // ZTE
                '/(zte)-(\w*)/i',
                '/(alcatel|geeksphone|nexian|panasonic|(?=;\s)sony)[_\s-]?([\w-]*)/i' // Alcatel/GeeksPhone/Nexian/Panasonic/Sony
            ], [self::VENDOR, [self::MODEL, '/_/', ' '], [self::TYPE, self::MOBILE]], [

                // Acer
                '/droid[x\d\.\s;]+\s([ab][1-7]\-?[0178a]\d\d?)/i'
            ], [self::MODEL, [self::VENDOR, 'Acer'], [self::TYPE, self::TABLET]], [

                // Meizu
                '/droid.+;\s(m[1-5]\snote)\sbuild/i',
                '/\bmz-([\w-]{2,})/i'
            ], [self::MODEL, [self::VENDOR, 'Meizu'], [self::TYPE, self::MOBILE]], [

                // MIXED
                '/(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus|dell|meizu|motorola|polytron)[\s_-]?([\w-]*)/i',
                // BlackBerry/BenQ/Palm/Sony-Ericsson/Acer/Asus/Dell/Meizu/Motorola/Polytron
                '/(hp)\s([\w\s]+\w)/i',                                               // HP iPAQ
                '/(asus)-?(\w+)/i',                                                   // Asus
                '/(microsoft);\s(lumia[\s\w]+)/i',                                    // Microsoft Lumia
                '/(lenovo)[_\s-]?([\w-]+)/i',                                         // Lenovo
                '/linux;.+(jolla);/i',                                                // Jolla
                '/droid.+;\s(oppo)\s?([\w\s]+)\sbuild/i'                              // OPPO
            ], [self::VENDOR, self::MODEL, [self::TYPE, self::MOBILE]], [

                '/(archos)\s(gamepad2?)/i',                                           // Archos
                '/(hp).+(touchpad(?!.+tablet)|tablet)/i',                             // HP TouchPad
                '/(kindle)\/([\w\.]+)/i',                                             // Kindle
                '/\s(nook)[\w\s]+build\/(\w+)/i',                                     // Nook
                '/(dell)\s(strea[kpr\s\d]*[\dko])/i',                                 // Dell Streak
                '/[;\/]\s?(le[\s\-]+pan)[\s\-]+(\w{1,9})\sbuild/i',                   // Le Pan Tablets
                '/[;\/]\s?(trinity)[\-\s]*(t\d{3})\sbuild/i',                         // Trinity Tablets
                '/\b(gigaset)[\s\-]+(q\w{1,9})\sbuild/i',                             // Gigaset Tablets
                '/\b(vodafone)\s([\w\s]+)(?:\)|\sbuild)/i'                            // Vodafone
            ], [self::VENDOR, self::MODEL, [self::TYPE, self::TABLET]], [

                '/\s(surface\sduo)\s/i'                                               // Surface Duo
            ], [self::MODEL, [self::VENDOR, 'Microsoft'], [self::TYPE, self::TABLET]], [
                '/droid\s[\d\.]+;\s(fp\du?)\sbuild/i'
            ], [self::MODEL, [self::VENDOR, 'Fairphone'], [self::TYPE, self::MOBILE]], [
                '/\s(u304aa)\sbuild/i'                                                // AT&T
            ], [self::MODEL, [self::VENDOR, 'AT&T'], [self::TYPE, self::MOBILE]], [
                '/sie-(\w*)/i'                                                        // Siemens
            ], [self::MODEL, [self::VENDOR, 'Siemens'], [self::TYPE, self::MOBILE]], [
                '/[;\/]\s?(rct\w+)\sbuild/i'                                          // RCA Tablets
            ], [self::MODEL, [self::VENDOR, 'RCA'], [self::TYPE, self::TABLET]], [
                '/[;\/\s](venue[\d\s]{2,7})\sbuild/i'                                 // Dell Venue Tablets
            ], [self::MODEL, [self::VENDOR, 'Dell'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?(q(?:mv|ta)\w+)\sbuild/i'                                   // Verizon Tablet
            ], [self::MODEL, [self::VENDOR, 'Verizon'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s(?:barnes[&\s]+noble\s|bn[rt])([\w\s\+]*)\sbuild/i'          // Barnes & Noble Tablet
            ], [self::MODEL, [self::VENDOR, 'Barnes & Noble'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s(tm\d{3}\w+)\sbuild/i'
            ], [self::MODEL, [self::VENDOR, 'NuVision'], [self::TYPE, self::TABLET]], [
                '/;\s(k88)\sbuild/i'                                                  // ZTE K Series Tablet
            ], [self::MODEL, [self::VENDOR, 'ZTE'], [self::TYPE, self::TABLET]], [
                '/;\s(nx\d{3}j)\sbuild/i'                                             // ZTE Nubia
            ], [self::MODEL, [self::VENDOR, 'ZTE'], [self::TYPE, self::MOBILE]], [
                '/[;\/]\s?(gen\d{3})\sbuild.*49h/i'                                   // Swiss GEN Mobile
            ], [self::MODEL, [self::VENDOR, 'Swiss'], [self::TYPE, self::MOBILE]], [
                '/[;\/]\s?(zur\d{3})\sbuild/i'                                        // Swiss ZUR Tablet
            ], [self::MODEL, [self::VENDOR, 'Swiss'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?((zeki)?tb.*\b)\sbuild/i'                                   // Zeki Tablets
            ], [self::MODEL, [self::VENDOR, 'Zeki'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s([yr]\d{2})\sbuild/i',
                '/[;\/]\s(dragon[\-\s]+touch\s|dt)(\w{5})\sbuild/i'                   // Dragon Touch Tablet
            ], [[self::VENDOR, 'Dragon Touch'], self::MODEL, [self::TYPE, self::TABLET]], [
                '/[;\/]\s?(ns-?\w{0,9})\sbuild/i'                                     // Insignia Tablets
            ], [self::MODEL, [self::VENDOR, 'Insignia'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?((nxa|Next)-?\w{0,9})\sbuild/i'                             // NextBook Tablets
            ], [self::MODEL, [self::VENDOR, 'NextBook'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?(xtreme\_)?(v(1[045]|2[015]|[3469]0|7[05]))\sbuild/i'
            ], [[self::VENDOR, 'Voice'], self::MODEL, [self::TYPE, self::MOBILE]], [                    // Voice Xtreme Phones
                '/[;\/]\s?(lvtel\-)?(v1[12])\sbuild/i'                                // LvTel Phones
            ], [[self::VENDOR, 'LvTel'], self::MODEL, [self::TYPE, self::MOBILE]], [
                '/;\s(ph-1)\s/i'
            ], [self::MODEL, [self::VENDOR, 'Essential'], [self::TYPE, self::MOBILE]], [                // Essential PH-1
                '/[;\/]\s?(v(100md|700na|7011|917g).*\b)\sbuild/i'                    // Envizen Tablets
            ], [self::MODEL, [self::VENDOR, 'Envizen'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?(trio[\s\w\-\.]+)\sbuild/i'                                 // MachSpeed Tablets
            ], [self::MODEL, [self::VENDOR, 'MachSpeed'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?tu_(1491)\sbuild/i'                                         // Rotor Tablets
            ], [self::MODEL, [self::VENDOR, 'Rotor'], [self::TYPE, self::TABLET]], [
                '/(shield[\w\s]+)\sbuild/i'                                           // Nvidia Shield Tablets
            ], [self::MODEL, [self::VENDOR, 'Nvidia'], [self::TYPE, self::TABLET]], [
                '/(sprint)\s(\w+)/i'                                                  // Sprint Phones
            ], [self::VENDOR, self::MODEL, [self::TYPE, self::MOBILE]], [
                '/(kin\.[onetw]{3})/i'                                                // Microsoft Kin
            ], [[self::MODEL, '/./', ' '], [self::VENDOR, 'Microsoft'], [self::TYPE, self::MOBILE]], [
                '/droid\s[\d\.]+;\s(cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i'     // Zebra
            ], [self::MODEL, [self::VENDOR, 'Zebra'], [self::TYPE, self::TABLET]], [
                '/droid\s[\d\.]+;\s(ec30|ps20|tc[2-8]\d[kx])\)/i'
            ], [self::MODEL, [self::VENDOR, 'Zebra'], [self::TYPE, self::MOBILE]], [

                ///////////////////
                // CONSOLES
                ///////////////////

                '/\s(ouya)\s/i',                                                      // Ouya
                '/(nintendo)\s([wids3utch]+)/i'                                       // Nintendo
            ], [self::VENDOR, self::MODEL, [self::TYPE, self::CONSOLE]], [
                '/droid.+;\s(shield)\sbuild/i'                                        // Nvidia
            ], [self::MODEL, [self::VENDOR, 'Nvidia'], [self::TYPE, self::CONSOLE]], [
                '/(playstation\s[345portablevi]+)/i'                                  // Playstation
            ], [self::MODEL, [self::VENDOR, 'Sony'], [self::TYPE, self::CONSOLE]], [
                '/[\s\(;](xbox(?:\sone)?(?!;\sxbox))[\s\);]/i'                        // Microsoft Xbox
            ], [self::MODEL, [self::VENDOR, 'Microsoft'], [self::TYPE, self::CONSOLE]], [

                ///////////////////
                // SMARTTVS
                ///////////////////

                '/smart-tv.+(samsung)/i'                                              // Samsung
            ], [self::VENDOR, [self::TYPE, self::SMARTTV]], [
                '/hbbtv.+maple;(\d+)/i'
            ], [[self::MODEL, '/^/', 'SmartTV'], [self::VENDOR, 'Samsung'], [self::TYPE, self::SMARTTV]], [
                '/(?:linux;\snetcast.+smarttv|lg\snetcast\.tv-201\d)/i',              // LG SmartTV
            ], [[self::VENDOR, 'LG'], [self::TYPE, self::SMARTTV]], [
                '/(apple)\s?tv/i'                                                     // Apple TV
            ], [self::VENDOR, [self::MODEL, 'Apple TV'], [self::TYPE, self::SMARTTV]], [
                '/crkey/i'                                                            // Google Chromecast
            ], [[self::MODEL, 'Chromecast'], [self::VENDOR, 'Google'], [self::TYPE, self::SMARTTV]], [
                '/droid.+aft([\w])(\sbuild\/|\))/i'                                   // Fire TV
            ], [self::MODEL, [self::VENDOR, 'Amazon'], [self::TYPE, self::SMARTTV]], [
                '/\(dtv[\);].+(aquos)/i'                                              // Sharp
            ], [self::MODEL, [self::VENDOR, 'Sharp'], [self::TYPE, self::SMARTTV]], [
                '/hbbtv\/\d+\.\d+\.\d+\s+\([\w\s]*;\s*(\w[^;]*);([^;]*)/i'            // HbbTV devices
            ], [[self::VENDOR, function ($str) {return $this->util->trim($str);}], [self::MODEL, function ($str) {return $this->util->trim($str);}], [self::TYPE, self::SMARTTV]], [
                '/[\s\/\(](android\s|smart[-\s]?|opera\s)tv[;\)\s]/i'                 // SmartTV from Unidentified Vendors
            ], [[self::TYPE, self::SMARTTV]], [

                ///////////////////
                // WEARABLES
                ///////////////////

                '/((pebble))app\/[\d\.]+\s/i'                                         // Pebble
            ], [self::VENDOR, self::MODEL, [self::TYPE, self::WEARABLE]], [
                '/droid.+;\s(glass)\s\d/i'                                            // Google Glass
            ], [self::MODEL, [self::VENDOR, 'Google'], [self::TYPE, self::WEARABLE]], [
                '/droid\s[\d\.]+;\s(wt63?0{2,3})\)/i'
            ], [self::MODEL, [self::VENDOR, 'Zebra'], [self::TYPE, self::WEARABLE]], [

                ///////////////////
                // EMBEDDED
                ///////////////////

                '/(tesla)(?:\sqtcarbrowser|\/20[12]\d\.[\w\.-]+)/i'                   // Tesla
            ], [self::VENDOR, [self::TYPE, self::EMBEDDED]], [

                ////////////////////
                // MIXED (GENERIC)
                ///////////////////

                '/droid .+?; ([^;]+?)(?: build|\) applewebkit).+? mobile safari/i'    // Android Phones from Unidentified Vendors
            ], [self::MODEL, [self::TYPE, self::MOBILE]], [
                '/droid .+?;\s([^;]+?)(?: build|\) applewebkit).+?(?! mobile) safari/i'  // Android Tablets from Unidentified Vendors
            ], [self::MODEL, [self::TYPE, self::TABLET]], [
                '/\s(tablet|tab)[;\/]/i',                                             // Unidentifiable Tablet
                '/\s(mobile)(?:[;\/]|\ssafari)/i'                                     // Unidentifiable Mobile
            ], [[self::MODEL, function ($str) {return $this->util->lowerize($str);}]], [
                '/(android[\w\.\s\-]{0,9});.+build/i'                                 // Generic Android Device
            ], [self::MODEL, [self::VENDOR, 'Generic']], [
                '/(phone)/i'
            ], [[self::TYPE, self::MOBILE]]
            ],

            'engine' => [[

                '/windows.+\sedge\/([\w\.]+)/i'                                       // EdgeHTML
            ], [self::VERSION, [self::NAME, 'EdgeHTML']], [

                '/(presto)\/([\w\.]+)/i',                                             // Presto
                '/(webkit|trident|netfront|netsurf|amaya|lynx|w3m)\/([\w\.]+)/i',     // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m
                '/(khtml|tasman|links)[\/\s]\(?([\w\.]+)/i',                          // KHTML/Tasman/Links
                '/(icab)[\/\s]([23]\.[\d\.]+)/i'                                      // iCab
            ], [self::NAME, self::VERSION], [

                '/rv\:([\w\.]+).*(gecko)/i'                                           // Gecko
            ], [self::VERSION, self::NAME]
            ],

            'os' => [[

                // Windows based
                '/microsoft\s(windows)\s(vista|xp)/i'                                 // Windows (iTunes)
            ], [self::NAME, self::VERSION], [
                '/(windows)\snt\s6\.2;\s(arm)/i',                                     // Windows RT
                '/(windows\sphone(?:\sos)*)[\s\/]?([\d\.\s]+\w)*/i',                  // Windows Phone
                '/(windows\smobile|windows)[\s\/]?([ntce\d\.\s]+\w)/i'
            ], [self::NAME, [self::VERSION, function ($str, $map) {
                return $this->mapper->str($str, $map);
            }, $this->maps['os']['windows']['version']]], [
                '/(win(?=3|9|n)|win\s9x\s)([nt\d\.]+)/i'
            ], [[self::NAME, 'Windows'], [self::VERSION, function ($str, $map) {
                return $this->mapper->str($str, $map);
            }, $this->maps['os']['windows']['version']]], [

                // Mobile/Embedded OS
                '/\((bb)(10);/i'                                                      // BlackBerry 10
            ], [[self::NAME, 'BlackBerry'], self::VERSION], [
                '/(blackberry)\w*\/?([\w\.]+)*/i',                                    // Blackberry
                '/(tizen)[\/\s]([\w\.]+)/i',                                          // Tizen
                '/(android|webos|palm\sos|qnx|bada|rim\stablet\sos|meego|contiki)[\/\s-]?([\w\.]+)*/i',
                // Android/WebOS/Palm/QNX/Bada/RIM/MeeGo/Contiki
                '/linux;.+(sailfish);/i'                                              // Sailfish OS
            ], [self::NAME, self::VERSION], [
                '/(symbian\s?os|symbos|s60(?=;))[\/\s-]?([\w\.]+)*/i'                 // Symbian
            ], [[self::NAME, 'Symbian'], self::VERSION], [
                '/\((series40);/i'                                                    // Series 40
            ], [self::NAME], [
                '/mozilla.+\(mobile;.+gecko.+firefox/i'                               // Firefox OS
            ], [[self::NAME, 'Firefox OS'], self::VERSION], [

                // Console
                '/(nintendo|playstation)\s([wids34portablevu]+)/i',                   // Nintendo/Playstation

                // GNU/Linux based
                '/(mint)[\/\s\(]?(\w+)*/i',                                           // Mint
                '/(mageia|vectorlinux)[;\s]/i',                                       // Mageia/VectorLinux
                '/(joli|[kxln]?ubuntu|debian|[open]*suse|gentoo|(?=\s)arch|slackware|fedora|mandriva|centos|pclinuxos|redhat|zenwalk|linpus)[\/\s-]?(?!chrom)([\w\.-]+)*/i',
                // Joli/Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware
                // Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus
                '/(hurd|linux)\s?([\w\.]+)*/i',                                       // Hurd/Linux
                '/(gnu)\s?([\w\.]+)*/i'                                               // GNU
            ], [self::NAME, self::VERSION], [

                '/(cros)\s[\w]+\s([\w\.]+\w)/i'                                       // Chromium OS
            ], [[self::NAME, 'Chromium OS'], self::VERSION], [

                // Solaris
                '/(sunos)\s?([\w\.]+\d)*/i'                                           // Solaris
            ], [[self::NAME, 'Solaris'], self::VERSION], [

                // BSD based
                '/\s([frentopc-]{0,4}bsd|dragonfly)\s?([\w\.]+)*/i'                   // FreeBSD/NetBSD/OpenBSD/PC-BSD/DragonFly
            ], [self::NAME, self::VERSION], [

                '/(haiku)\s(\w+)/i'                                                  // Haiku
            ], [self::NAME, self::VERSION], [

                '/cfnetwork\/.+darwin/i',
                '/ip[honead]+(?:.*os\s([\w]+)*\slike\smac|;\sopera)/i'                // iOS
            ], [[self::VERSION, '/_/', '.'], [self::NAME, 'iOS']], [

                '/(mac\sos\sx)\s?([\w\s\.]+\w)*/i',
                '/(macintosh|mac(?=_powerpc)\s)/i'                                    // Mac OS
            ], [[self::NAME, 'Mac OS'], [self::VERSION, '/_/', '.']], [

                // Other
                '/((?:open)?solaris)[\/\s-]?([\w\.]+)*/i',                            // Solaris
                '/(aix)\s((\d)(?=\.|\)|\s)[\w\.]*)*/i',                               // AIX
                '/(plan\s9|minix|beos|os\/2|amigaos|morphos|risc\sos|openvms)/i',
                // Plan9/Minix/BeOS/OS2/AmigaOS/MorphOS/RISCOS/OpenVMS
                '/(unix)\s?([\w\.]+)*/i'                                              // UNIX
            ], [self::NAME, self::VERSION]
            ]
        ];


        if (is_object($uastring)) {
            $extensions = $uastring;
            $uastring = null;
        }

        if (is_null($uastring) && isset($_SERVER['HTTP_USER_AGENT'])) {
            $this->ua = $_SERVER['HTTP_USER_AGENT'];
        } else {
            $this->ua = $uastring;
        }

        if ($extensions) $this->rgxmap = $this->util->extend($this->rgxmap, $extensions);

    }

    /**
     * @return array
     */
    public function getBrowser()
    {
        $browser = ['name' => null, 'version' => null];
        $this->mapper->rgx($browser, $this->ua, $this->rgxmap['browser']);
        $browser['major'] = $this->util->major($browser['version']);
        return $browser;
    }

    /**
     * @return array
     */
    public function getCPU()
    {
        $cpu = ['architecture' => null];
        $this->mapper->rgx($cpu, $this->ua, $this->rgxmap['cpu']);
        return $cpu;
    }

    /**
     * @return array
     */
    public function getDevice()
    {
        $device = ['vendor' => null, 'model' => null, 'type' => null];
        $this->mapper->rgx($device, $this->ua, $this->rgxmap['device']);
        return $device;
    }

    /**
     * @return array
     */
    public function getEngine()
    {
        $engine = ['name' => null, 'version' => null];
        $this->mapper->rgx($engine, $this->ua, $this->rgxmap['engine']);
        return $engine;
    }

    /**
     * @return array
     */
    public function getOS()
    {
        $os = ['name' => null, 'version' => null];
        $this->mapper->rgx($os, $this->ua, $this->rgxmap['os']);
        return $os;
    }

    /**
     * @return array
     */
    public function getResult()
    {
        return [
            'ua' => $this->getUA(),
            'browser' => $this->getBrowser(),
            'engine' => $this->getEngine(),
            'os' => $this->getOS(),
            'device' => $this->getDevice(),
            'cpu' => $this->getCPU()
        ];
    }

    /**
     * @return null|string
     */
    public function getUA()
    {
        return $this->ua;
    }

    /**
     * @param $ua
     * @return $this
     */
    public function setUA($ua)
    {
        $this->ua = $ua;
        return $this;
    }
}