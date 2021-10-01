<?php

namespace Motikan2010\UAParser;

class UAParser
{
    const LIBVERSION    = '0.7.28';
    const _EMPTY        = '';
    const UNKNOWN       = '?';
    const FUNC_TYPE     = 'function';
    const UNDEF_TYPE    = 'undefined';
    const OBJ_TYPE      = 'object';
    const STR_TYPE      = 'string';
    const MAJOR         = 'major'; // deprecated
    const MODEL         = 'model';
    const NAME          = 'name';
    const TYPE          = 'type';
    const VENDOR        = 'vendor';
    const VERSION       = 'version';
    const ARCHITECTURE  = 'architecture';
    const CONSOLE       = 'console';
    const MOBILE        = 'mobile';
    const TABLET        = 'tablet';
    const SMARTTV       = 'smarttv';
    const WEARABLE      = 'wearable';
    const EMBEDDED      = 'embedded';

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
            'browser' => [[

                '/\b(?:crmo|crios)\/([\w\.]+)/i'                                      // Chrome for Android/iOS
                ], [self::VERSION, [self::NAME, 'Chrome']], [
                '/edg(?:e|ios|a)?\/([\w\.]+)/i'                                       // Microsoft Edge
                ], [self::VERSION, [self::NAME, 'Edge']], [

                // Presto based
                '/(opera\smini)\/([\w\.-]+)/i',                                       // Opera Mini
                '/(opera\s[mobiletab]{3,6})\b.+version\/([\w\.-]+)/i',                // Opera Mobi/Tablet
                '/(opera)(?:.+version\/|[\/\s]+)([\w\.]+)/i',                         // Opera
                ], [self::NAME, self::VERSION], [
                '/opios[\/\s]+([\w\.]+)/i'                                            // Opera mini on iphone >= 8.0
                ], [self::VERSION, [self::NAME, 'Opera Mini']], [
                '/\sopr\/([\w\.]+)/i'                                                 // Opera Webkit
                ], [self::VERSION, [self::NAME, 'Opera']], [

                // Mixed
                '/(kindle)\/([\w\.]+)/i',                                             // Kindle
                '/(lunascape|maxthon|netfront|jasmine|blazer)[\/\s]?([\w\.]*)/i',     // Lunascape/Maxthon/Netfront/Jasmine/Blazer
                // Trident based
                '/(avant\s|iemobile|slim)(?:browser)?[\/\s]?([\w\.]*)/i',             // Avant/IEMobile/SlimBrowser
                '/(ba?idubrowser)[\/\s]?([\w\.]+)/i',                                 // Baidu Browser
                '/(?:ms|\()(ie)\s([\w\.]+)/i',                                        // Internet Explorer

                // Webkit/KHTML based
                '/(flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser|quark|qupzilla|falkon)\/([\w\.-]+)/i',
                                                                                        // Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/Iridium/PhantomJS/Bowser/QupZilla/Falkon
                '/(rekonq|puffin|brave|whale|qqbrowserlite|qq)\/([\w\.]+)/i',           // Rekonq/Puffin/Brave/Whale/QQBrowserLite/QQ, aka ShouQ
                '/(weibo)__([\d\.]+)/i'                                                 // Weibo
                ], [self::NAME, self::VERSION], [
                '/(?:[\s\/]uc?\s?browser|(?:juc.+)ucweb)[\/\s]?([\w\.]+)/i'             // UCBrowser
                ], [self::VERSION, [self::NAME, 'UCBrowser']], [
                '/(?:windowswechat)?\sqbcore\/([\w\.]+)\b.*(?:windowswechat)?/i'      // WeChat Desktop for Windows Built-in Browser
                ], [self::VERSION, [self::NAME, 'WeChat(Win) Desktop']], [
                '/micromessenger\/([\w\.]+)/i'                                        // WeChat
                ], [self::VERSION, [self::NAME, 'WeChat']], [
                '/konqueror\/([\w\.]+)/i'                                             // Konqueror
                ], [self::VERSION, [self::NAME, 'Konqueror']], [
                '/trident.+rv[:\s]([\w\.]{1,9})\b.+like\sgecko/i'                     // IE11
                ], [self::VERSION, [self::NAME, 'IE']], [
                '/yabrowser\/([\w\.]+)/i'                                             // Yandex
                ], [self::VERSION, [self::NAME, 'Yandex']], [
                '/(avast|avg)\/([\w\.]+)/i'                                           // Avast/AVG Secure Browser
                ], [[self::NAME, '/(.+)/', '$1 Secure Browser'], self::VERSION], [
                '/focus\/([\w\.]+)/i'                                                 // Firefox Focus
                ], [self::VERSION, [self::NAME, 'Firefox Focus']], [
                '/opt\/([\w\.]+)/i'                                                   // Opera Touch
                ], [self::VERSION, [self::NAME, 'Opera Touch']], [
                '/coc_coc_browser\/([\w\.]+)/i'                                       // Coc Coc Browser
                ], [self::VERSION, [self::NAME, 'Coc Coc']], [
                '/dolfin\/([\w\.]+)/i'                                                // Dolphin
                ], [self::VERSION, [self::NAME, 'Dolphin']], [
                '/coast\/([\w\.]+)/i'                                                 // Opera Coast
                ], [self::VERSION, [self::NAME, 'Opera Coast']], [
                '/xiaomi\/miuibrowser\/([\w\.]+)/i'                                  // MIUI Browser
                ], [self::VERSION, [self::NAME, 'MIUI Browser']], [
                '/fxios\/([\w\.-]+)/i'                                                // Firefox for iOS
                ], [self::VERSION, [self::NAME, 'Firefox']], [
                '/(qihu|qhbrowser|qihoobrowser|360browser)/i'                         // 360
                ], [[self::NAME, '360 Browser']], [
                '/(oculus|samsung|sailfish)browser\/([\w\.]+)/i'
                ], [[self::NAME, '/(.+)/', '$1 Browser'], self::VERSION], [                       // Oculus/Samsung/Sailfish Browser
                '/(comodo_dragon)\/([\w\.]+)/i'                                       // Comodo Dragon
                ], [[self::NAME, '/_/', ' '], self::VERSION], [
                '/\s(electron)\/([\w\.]+)\ssafari/i',                                 // Electron-based App
                '/(tesla)(?:\sqtcarbrowser|\/(20[12]\d\.[\w\.-]+))/i',                // Tesla
                '/m?(qqbrowser|baiduboxapp|2345Explorer)[\/\s]?([\w\.]+)/i'           // QQBrowser/Baidu App/2345 Browser
                ], [self::NAME, self::VERSION], [
                '/(MetaSr)[\/\s]?([\w\.]+)/i',                                        // SouGouBrowser
                '/(LBBROWSER)/i'                                                      // LieBao Browser
                ], [self::NAME], [

                // WebView
                '/;fbav\/([\w\.]+);/i'                                                // Facebook App for iOS & Android with version
                ], [self::VERSION, [self::NAME, 'Facebook']], [
                '/FBAN\/FBIOS|FB_IAB\/FB4A/i'                                         // Facebook App for iOS & Android without version
                ], [[self::NAME, 'Facebook']], [
                '/safari\s(line)\/([\w\.]+)/i',                                       // Line App for iOS
                '/\b(line)\/([\w\.]+)\/iab/i',                                        // Line App for Android
                '/(chromium|instagram)[\/\s]([\w\.-]+)/i'                             // Chromium/Instagram
                ], [self::NAME, self::VERSION], [
                '/\bgsa\/([\w\.]+)\s.*safari\//i'                                     // Google Search Appliance on iOS
                ], [self::VERSION, [self::NAME, 'GSA']], [

                '/headlesschrome(?:\/([\w\.]+)|\s)/i'                                 // Chrome Headless
                ], [self::VERSION, [self::NAME, 'Chrome Headless']], [

                '/\swv\).+(chrome)\/([\w\.]+)/i'                                      // Chrome WebView
                ], [[self::NAME, 'Chrome WebView'], self::VERSION], [

                '/droid.+\sversion\/([\w\.]+)\b.+(?:mobile\ssafari|safari)/i'         // Android Browser
                ], [self::VERSION, [self::NAME, 'Android Browser']], [

                '/(chrome|omniweb|arora|[tizenoka]{5}\s?browser)\/v?([\w\.]+)/i'      // Chrome/OmniWeb/Arora/Tizen/Nokia
                ], [self::NAME, self::VERSION], [

                '/version\/([\w\.]+)\s.*mobile\/\w+\s(safari)/i'                      // Mobile Safari
                ], [self::VERSION, [self::NAME, 'Mobile Safari']], [
                '/version\/([\w\.]+)\s.*(mobile\s?safari|safari)/i'                   // Safari & Safari Mobile
                ], [self::VERSION, self::NAME], [
                '/webkit.+?(mobile\s?safari|safari)(\/[\w\.]+)/i'                     // Safari < 3.0
                ], [self::NAME, [self::VERSION, function ($str, $map) {return $this->mapper->str($str, $map);}, $this->maps['browser']['oldsafari']['version']]], [

                '/(webkit|khtml)\/([\w\.]+)/i'
                ], [self::NAME, self::VERSION], [

                // Gecko based
                '/(navigator|netscape)\/([\w\.-]+)/i'                                 // Netscape
                ], [[self::NAME, 'Netscape'], self::VERSION], [
                '/ile\svr;\srv:([\w\.]+)\).+firefox/i'                                // Firefox Reality
                ], [self::VERSION, [self::NAME, 'Firefox Reality']], [
                '/ekiohf.+(flow)\/([\w\.]+)/i',                                       // Flow
                '/(swiftfox)/i',                                                      // Swiftfox
                '/(icedragon|iceweasel|camino|chimera|fennec|maemo\sbrowser|minimo|conkeror)[\/\s]?([\w\.\+]+)/i',
                // IceDragon/Iceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
                '/(firefox|seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\/([\w\.-]+)$/i',
                // Firefox/SeaMonkey/K-Meleon/IceCat/IceApe/Firebird/Phoenix
                '/(firefox)\/([\w\.]+)\s[\w\s\-]+\/[\w\.]+$/i',                       // Other Firefox-based
                '/(mozilla)\/([\w\.]+)\s.+rv\:.+gecko\/\d+/i',                        // Mozilla

                // Other
                '/(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir)[\/\s]?([\w\.]+)/i',
                                                                                        // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf/Sleipnir
                '/(links)\s\(([\w\.]+)/i',                                            // Links
                '/(gobrowser)\/?([\w\.]*)/i',                                         // GoBrowser
                '/(ice\s?browser)\/v?([\w\._]+)/i',                                   // ICE Browser
                '/(mosaic)[\/\s]([\w\.]+)/i'                                          // Mosaic
                ], [self::NAME, self::VERSION]

            ],

            'cpu' => [[

                '/(?:(amd|x(?:(?:86|64)[-_])?|wow|win)64)[;\)]/i'                       // AMD64 (x64)
                ], [[self::ARCHITECTURE, 'amd64']], [

                '/(ia32(?=;))/i'                                                        // IA32 (quicktime)
                ], [[self::ARCHITECTURE, function ($str) {return $this->util->lowerize($str);}]], [

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
                ], [[self::ARCHITECTURE, '/ower/', '', function ($str) {return $this->util->lowerize($str);}]], [

                '/(sun4\w)[;\)]/i'                                                      // SPARC
                ], [[self::ARCHITECTURE, 'sparc']], [

                '/((?:avr32|ia64(?=;))|68k(?=\))|\barm(?=v(?:[1-7]|[5-7]1)l?|;|eabi)|(?=atmel )avr|(?:irix|mips|sparc)(?:64)?\b|pa-risc)/i'
                                                                                        // IA64, 68K, ARM/64, AVR/32, IRIX/64, MIPS/64, SPARC/64, PA-RISC
                ], [[self::ARCHITECTURE, function ($str) {return $this->util->lowerize($str);}]]
            ],

            'device' => [[

                //////////////////////////
                // MOBILES & TABLETS
                // Ordered by popularity
                /////////////////////////

                // Samsung
                '/\b(sch-i[89]0\d|shw-m380s|sm-[pt]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus\s10)/i'
                ], [self::MODEL, [self::VENDOR, 'Samsung'], [self::TYPE, self::TABLET]], [
                '/\b((?:s[cgp]h|gt|sm)-\w+|galaxy nexus)/i',
                '/samsung[- ]([-\w]+)/i',
                '/sec-(sgh\w+)/i'
                ], [self::MODEL, [self::VENDOR, 'Samsung'], [self::TYPE, self::MOBILE]], [

                // Apple
                '/\((ip(?:hone|od)[\w ]*);/i'                                       // iPod/iPhone
                ], [self::MODEL, [self::VENDOR, 'Apple'], [self::TYPE, self::MOBILE]], [
                '/\((ipad);[-\w\),; ]+apple/i',                                     // iPad
                '/applecoremedia\/[\w\.]+ \((ipad)/i',
                '/\b(ipad)\d\d?,\d\d?[;\]].+ios/i',
                ], [self::MODEL, [self::VENDOR, 'Apple'], [self::TYPE, self::TABLET]], [

                // Huawei
                '/\b((?:agr|ags[23]|bah2?|sht?)-a?[lw]\d{2})/i'
                ], [self::MODEL, [self::VENDOR, 'Huawei'], [self::TYPE, self::TABLET]], [
                '/d\/huawei([\w\s-]+)[;\)]/i',
                '/\b(nexus\s6p|vog-[at]?l\d\d|ane-[at]?l[x\d]\d|eml-a?l\d\da?|lya-[at]?l\d[\dc]|clt-a?l\d\di?|ele-l\d\d)/i',
                '/\b(\w{2,4}-[atu][ln][01259][019])[;\)\s]/i'
                ], [self::MODEL, [self::VENDOR, 'Huawei'], [self::TYPE, self::MOBILE]], [

                // Xiaomi
                '/\b(poco[\w ]+)(?: bui|\))/i',                             // Xiaomi POCO
                '/\b; (\w+) build\/hm\1/i',                                 // Xiaomi Hongmi 'numeric' models
                '/\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i',                   // Xiaomi Hongmi
                '/\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i',         // Xiaomi Redmi
                '/\b(mi[\s\-_]?(?:a\d|one|one[\s_]plus|note lte)?[\s_]?(?:\d?\w?)[\s_]?(?:plus)?)\sbuild/i' // Xiaomi Mi
                ], [[self::MODEL, '/_/', ' '], [self::VENDOR, 'Xiaomi'], [self::TYPE, self::MOBILE]], [
                '/\b(mi[-_ ]?(?:pad)(?:[\w_ ]+))(?: bui|\))/i'              // Mi Pad tablets
                ], [[self::MODEL, '/_/', ' '], [self::VENDOR, 'Xiaomi'], [self::TYPE, self::TABLET]], [

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
                ], [self::MODEL, [self::VENDOR, 'BlackBerry'], [self::TYPE, self::MOBILE]], [

                // Asus
                '/(?:\b|asus_)(transfo[prime\s]{4,10}\s\w+|eeepc|slider\s\w+|nexus\s7|padfone|p00[cj])/i'
                ], [self::MODEL, [self::VENDOR, 'ASUS'], [self::TYPE, self::TABLET]], [
                '/\s(z[es]6[027][01][km][ls]|zenfone\s\d\w?)\b/i'
                ], [self::MODEL, [self::VENDOR, 'ASUS'], [self::TYPE, self::MOBILE]], [

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
                '/(alcatel|geeksphone|nexian|panasonic|(?=;\s)sony)[_\s-]?([\w-]*)/i'       // Alcatel/GeeksPhone/Nexian/Panasonic/Sony
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
                '/(hp)\s([\w\s]+\w)/i',                                                 // HP iPAQ
                '/(asus)-?(\w+)/i',                                                     // Asus
                '/(microsoft);\s(lumia[\s\w]+)/i',                                      // Microsoft Lumia
                '/(lenovo)[_\s-]?([\w-]+)/i',                                           // Lenovo
                '/linux;.+(jolla);/i',                                                  // Jolla
                '/droid.+;\s(oppo)\s?([\w\s]+)\sbuild/i'                                // OPPO
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
                ], [[self::VENDOR, 'Voice'], self::MODEL, [self::TYPE, self::MOBILE]], [        // Voice Xtreme Phones
                '/[;\/]\s?(lvtel\-)?(v1[12])\sbuild/i'                                          // LvTel Phones
                ], [[self::VENDOR, 'LvTel'], self::MODEL, [self::TYPE, self::MOBILE]], [
                '/;\s(ph-1)\s/i'
                ], [self::MODEL, [self::VENDOR, 'Essential'], [self::TYPE, self::MOBILE]], [    // Essential PH-1
                '/[;\/]\s?(v(100md|700na|7011|917g).*\b)\sbuild/i'                              // Envizen Tablets
                ], [self::MODEL, [self::VENDOR, 'Envizen'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?(trio[\s\w\-\.]+)\sbuild/i'                                           // MachSpeed Tablets
                ], [self::MODEL, [self::VENDOR, 'MachSpeed'], [self::TYPE, self::TABLET]], [
                '/[;\/]\s?tu_(1491)\sbuild/i'                                                   // Rotor Tablets
                ], [self::MODEL, [self::VENDOR, 'Rotor'], [self::TYPE, self::TABLET]], [
                '/(shield[\w\s]+)\sbuild/i'                                                     // Nvidia Shield Tablets
                ], [self::MODEL, [self::VENDOR, 'Nvidia'], [self::TYPE, self::TABLET]], [
                '/(sprint)\s(\w+)/i'                                                            // Sprint Phones
                ], [self::VENDOR, self::MODEL, [self::TYPE, self::MOBILE]], [
                '/(kin\.[onetw]{3})/i'                                                          // Microsoft Kin
                ], [[self::MODEL, '/./', ' '], [self::VENDOR, 'Microsoft'], [self::TYPE, self::MOBILE]], [
                '/droid\s[\d\.]+;\s(cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i'               // Zebra
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

                '/smart-tv.+(samsung)/i'                                                    // Samsung
                ], [self::VENDOR, [self::TYPE, self::SMARTTV]], [
                '/hbbtv.+maple;(\d+)/i'
                ], [[self::MODEL, '/^/', 'SmartTV'], [self::VENDOR, 'Samsung'], [self::TYPE, self::SMARTTV]], [
                '/(?:linux;\snetcast.+smarttv|lg\snetcast\.tv-201\d)/i',                    // LG SmartTV
                ], [[self::VENDOR, 'LG'], [self::TYPE, self::SMARTTV]], [
                '/(apple)\s?tv/i'                                                           // Apple TV
                ], [self::VENDOR, [self::MODEL, 'Apple TV'], [self::TYPE, self::SMARTTV]], [
                '/crkey/i'                                                                  // Google Chromecast
                ], [[self::MODEL, 'Chromecast'], [self::VENDOR, 'Google'], [self::TYPE, self::SMARTTV]], [
                '/droid.+aft([\w])(\sbuild\/|\))/i'                                         // Fire TV
                ], [self::MODEL, [self::VENDOR, 'Amazon'], [self::TYPE, self::SMARTTV]], [
                '/\(dtv[\);].+(aquos)/i'                                                    // Sharp
                ], [self::MODEL, [self::VENDOR, 'Sharp'], [self::TYPE, self::SMARTTV]], [
                '/hbbtv\/\d+\.\d+\.\d+\s+\([\w\s]*;\s*(\w[^;]*);([^;]*)/i'                  // HbbTV devices
                ], [[self::VENDOR, function ($str) {return $this->util->trim($str);}], [self::MODEL, function ($str) {return $this->util->trim($str);}], [self::TYPE, self::SMARTTV]], [
                '/[\s\/\(](android\s|smart[-\s]?|opera\s)tv[;\)\s]/i'                       // SmartTV from Unidentified Vendors
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

                '/droid .+?; ([^;]+?)(?: build|\) applewebkit).+? mobile safari/i'              // Android Phones from Unidentified Vendors
                ], [self::MODEL, [self::TYPE, self::MOBILE]], [
                '/droid .+?;\s([^;]+?)(?: build|\) applewebkit).+?(?! mobile) safari/i'         // Android Tablets from Unidentified Vendors
                ], [self::MODEL, [self::TYPE, self::TABLET]], [
                '/\s(tablet|tab)[;\/]/i',                                                       // Unidentifiable Tablet
                '/\s(mobile)(?:[;\/]|\ssafari)/i'                                               // Unidentifiable Mobile
                ], [[self::MODEL, function ($str) {return $this->util->lowerize($str);}]], [
                '/(android[\w\.\s\-]{0,9});.+build/i'                                           // Generic Android Device
                ], [self::MODEL, [self::VENDOR, 'Generic']], [
                '/(phone)/i'
                ], [[self::TYPE, self::MOBILE]]
            ],

            'engine' => [[

                '/windows.+\sedge\/([\w\.]+)/i'                                 // EdgeHTML
                ], [self::VERSION, [self::NAME, 'EdgeHTML']], [

                '/webkit\/537\.36.+chrome\/(?!27)([\w\.]+)/i'                   // Blink
                ], [self::VERSION, [self::NAME, 'Blink']], [

                '/(presto)\/([\w\.]+)/i',                                       // Presto
                '/(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna)\/([\w\.]+)/i', // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m/Goanna
                '/ekioh(flow)\/([\w\.]+)/i',                                    // Flow
                '/(khtml|tasman|links)[\/\s]\(?([\w\.]+)/i',                    // KHTML/Tasman/Links
                '/(icab)[\/\s]([23]\.[\d\.]+)/i'                                // iCab
                ], [self::NAME, self::VERSION], [

                '/rv\:([\w\.]{1,9})\b.+(gecko)/i'                               // Gecko
                ], [self::VERSION, self::NAME]
            ],

            'os' => [[

                // Windows
                '/microsoft\s(windows)\s(vista|xp)/i'               // Windows (iTunes)
                ], [self::NAME, self::VERSION], [
                '/(windows)\snt\s6\.2;\s(arm)/i',                   // Windows RT
                '/(windows\sphone(?:\sos)*)[\s\/]?([\d\.\s\w]*)/i', // Windows Phone
                '/(windows\smobile|windows)[\s\/]?([ntce\d\.\s]+\w)(?!.+xbox)/i'
                ], [self::NAME, [self::VERSION, function ($str, $map) {return $this->mapper->str($str, $map);}, $this->maps['os']['windows']['version']]], [
                '/(win(?=3|9|n)|win\s9x\s)([nt\d\.]+)/i'
                ], [[self::NAME, 'Windows'], [self::VERSION, function ($str, $map) {return $this->mapper->str($str, $map);}, $this->maps['os']['windows']['version']]], [

                // iOS/macOS
                '/ip[honead]{2,4}\b(?:.*os\s([\w]+)\slike\smac|;\sopera)/i',
                '/cfnetwork\/.+darwin/i'
                ], [[self::VERSION, '/_/', '.'], [self::NAME, 'iOS']], [
                '/(mac\sos\sx)\s?([\w\s\.]*)/i',
                '/(macintosh|mac(?=_powerpc)\s)(?!.+haiku)/i'
                ], [[self::NAME, 'Mac OS'], [self::VERSION, '/_/', '.']], [

                // Mobile OSes
                '/(android|webos|palm\sos|qnx|bada|rim\stablet\sos|meego|sailfish|contiki)[\/\s-]?([\w\.]*)/i',
                '/(blackberry)\w*\/([\w\.]*)/i',
                '/(tizen|kaios)[\/\s]([\w\.]+)/i',
                '/\((series40);/i'
                ], [self::NAME, self::VERSION], [
                '/\(bb(10);/i'
                ], [self::VERSION, [self::NAME, 'BlackBerry']], [
                '/(?:symbian\s?os|symbos|s60(?=;)|series60)[\/\s-]?([\w\.]*)/i' // Symbian
                ], [self::VERSION, [self::NAME, 'Symbian']], [
                '/mozilla.+\(mobile;.+gecko.+firefox/i'
                ], [[self::NAME, 'Firefox OS']], [
                '/web0s;.+rt(tv)/i',
                '/\b(?:hp)?wos(?:browser)?\/([\w\.]+)/i'
                ], [self::VERSION, [self::NAME, 'webOS']], [

                // Google Chromecast
                '/crkey\/([\d\.]+)/i'                           // Google Chromecast
                ], [self::VERSION, [self::NAME, 'Chromecast']], [
                '/(cros)\s[\w]+\s([\w\.]+\w)/i'                 // Chromium OS
                ], [[self::NAME, 'Chromium OS'], self::VERSION],[

                // Console
                '/(nintendo|playstation)\s([wids345portablevuch]+)/i',
                '/(xbox);\s+xbox\s([^\);]+)/i',

                // GNU/Linux based
                '/(mint)[\/\s\(\)]?(\w*)/i',
                '/(mageia|vectorlinux)[;\s]/i',
                '/(joli|[kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?=\slinux)|slackware|fedora|mandriva|centos|pclinuxos|redhat|zenwalk|linpus|raspbian)(?:\sgnu\/linux)?(?:\slinux)?[\/\s-]?(?!chrom|package)([\w\.-]*)/i',
                                                                // Joli/Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware
                                                                // Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus
                '/(hurd|linux)\s?([\w\.]*)/i',
                '/(gnu)\s?([\w\.]*)/i',

                // BSD based
                '/\s([frentopc-]{0,4}bsd|dragonfly)\s?(?!amd|[ix346]{1,2}86)([\w\.]*)/i',
                '/(haiku)\s(\w+)/i'
                ], [self::NAME, self::VERSION], [

                // Other
                '/(sunos)\s?([\w\.\d]*)/i'
                ], [[self::NAME, 'Solaris'], self::VERSION], [
                '/((?:open)?solaris)[\/\s-]?([\w\.]*)/i',
                '/(aix)\s((\d)(?=\.|\)|\s)[\w\.])*/i',
                '/(plan\s9|minix|beos|os\/2|amigaos|morphos|risc\sos|openvms|fuchsia)/i',
                '/(unix)\s?([\w\.]*)/i'
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