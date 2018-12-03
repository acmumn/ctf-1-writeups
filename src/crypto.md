# Crypto

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.10.0/dist/katex.min.css" integrity="sha384-9eLZqc9ds8eNjO3TmqPeYcDj8n+Qfa4nuSiGYa6DjLNcv9BtN69ZIulL9+8CqC9Y" crossorigin="anonymous">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.10.0/dist/katex.min.js" integrity="sha384-K3vbOmF2BtaVai+Qk37uypf7VrgBubhQreNQe9aGsz9lB63dIFiQVlJbr92dw2Lx" crossorigin="anonymous"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.10.0/dist/contrib/auto-render.min.js" integrity="sha384-kmZOZB5ObwgQnS/DuDg6TScgOiWWBiVt0plIRkZCmE6rDZGrEOQeHM5PcHi+nyqe" crossorigin="anonymous"
    onload="renderMathInElement(document.body);"></script>

## Caesar Cipher (30)

Caesar cipher is just a shift cipher. Since there's only 26 possibilities we can even brute force it. Here's a program to brute force it:

```py
from string import ascii_lowercase
enc = "uapv{qji_sxs_ndj_jht_etcrxa_pcs_epetg}"
a = ord("a")
for i in range(26):
    m = ""
    for c in enc:
        if c in ascii_lowercase:
            m += chr((ord(c) - a + i) % 26 + a)
        else:
            m += c
    print(m)
```

Which gives this output:

```
uapv{qji_sxs_ndj_jht_etcrxa_pcs_epetg}
vbqw{rkj_tyt_oek_kiu_fudsyb_qdt_fqfuh}
wcrx{slk_uzu_pfl_ljv_gvetzc_reu_grgvi}
xdsy{tml_vav_qgm_mkw_hwfuad_sfv_hshwj}
yetz{unm_wbw_rhn_nlx_ixgvbe_tgw_itixk}
zfua{von_xcx_sio_omy_jyhwcf_uhx_jujyl}
agvb{wpo_ydy_tjp_pnz_kzixdg_viy_kvkzm}
bhwc{xqp_zez_ukq_qoa_lajyeh_wjz_lwlan}
cixd{yrq_afa_vlr_rpb_mbkzfi_xka_mxmbo}
djye{zsr_bgb_wms_sqc_nclagj_ylb_nyncp}
ekzf{ats_chc_xnt_trd_odmbhk_zmc_ozodq}
flag{but_did_you_use_pencil_and_paper}
gmbh{cvu_eje_zpv_vtf_qfodjm_boe_qbqfs}
hnci{dwv_fkf_aqw_wug_rgpekn_cpf_rcrgt}
iodj{exw_glg_brx_xvh_shqflo_dqg_sdshu}
jpek{fyx_hmh_csy_ywi_tirgmp_erh_tetiv}
kqfl{gzy_ini_dtz_zxj_ujshnq_fsi_ufujw}
lrgm{haz_joj_eua_ayk_vktior_gtj_vgvkx}
mshn{iba_kpk_fvb_bzl_wlujps_huk_whwly}
ntio{jcb_lql_gwc_cam_xmvkqt_ivl_xixmz}
oujp{kdc_mrm_hxd_dbn_ynwlru_jwm_yjyna}
pvkq{led_nsn_iye_eco_zoxmsv_kxn_zkzob}
qwlr{mfe_oto_jzf_fdp_apyntw_lyo_alapc}
rxms{ngf_pup_kag_geq_bqzoux_mzp_bmbqd}
synt{ohg_qvq_lbh_hfr_crapvy_naq_cncre}
tzou{pih_rwr_mci_igs_dsbqwz_obr_dodsf}
```

There it is, our flag sitting in plain sight: `flag{but_did_you_use_pencil_and_paper}`.

## RSA 1 (50)

In this challenge, we're given this information:

```
N = 595546813727
e = 101
d = 70757853773
c = 480953659518

Confused?
  N = public modulus
  e = public exponent
  d = private exponent
  c = ciphertext
Now try to decrypt it into the original message!
```

The way the RSA cryptosystem works is using a _public/private keypair_. These keys are related mathematically through a relationship such that to go from the plaintext message to the encrypted ciphertext, you must perform an irreversible operation using the _public_ key. Then, to go from the encrypted ciphertext back to the plaintext message, you perform an irreversible operation using the _private_ key. It happens that this irreversible operation is _modular exponentiation_, which is just regular exponentiation but the answer is taken modulo some modulus. The [Wikipedia page][1] goes into more detail about this topic, but this is all we need to solve this problem.

Since we're given the private exponent _and_ the modulus, the only thing we have to do is to perform the exponentiation to get the original message!

```
>>> pow(480953659518, 70757853773, 595546813727)
47286317
```

The flag is `flag{47286317}`.

## RSA 2 (70)

In this challenge, we're given the same thing as before, except there's no private key this time!

```
N = 1335595887054866149081
e = 65537
c = 1215965040794194819807

Hint: Is there a place that I can look up existing prime factors?
```

Per the hint, we can look up the prime factors of \\(N\\) on [factordb][2], which reveals to us that the prime factors are 34413284327 and 38810474303. We're not done yet! We have \\(p\\) and \\(q\\), the prime factors, but we don't have the private exponent yet. In order to find the private exponent, we have to use the relationship between \\(e\\), the public exponent, and \\(d\\), the private exponent: \\(ed \equiv 1 \mod \phi(N)\\).

\\(\phi(N)\\) is known as the [totient function][3], and is equal to the number of integers below \\(N\\) that are relatively prime to \\(N\\). For a prime number \\(p\\), \\(\phi(p)\\) would be \\(p - 1\\), since every integer except for itself is relatively prime to itself (1 counts, since formally, x and y are relatively prime if \\(\gcd(x, y) = 1\\)).

Another property of the totient function is that it's multiplicative, so \\(\phi(p) * \phi(q) = \phi(pq)\\). Lucky us, because \\(N = pq\\)! So \\(\phi(N) = \phi(p)\phi(q)\\), and since \\(p\\) and \\(q\\) are both prime, this product is equal to \\((p - 1)(q - 1)\\).

```
>>> tot = (34413284327 - 1) * (38810474303 - 1)
>>> tot
1335595886981642390452
```

Now, in order to find d, we will need to find the _modular inverse_ of \\(e \mod \phi(N)\\). This process uses the Euler method of finding greatest common denominator backwards. For the purposes of this answer, I'll use the Python implementation described [here][4].

```
>>> d = modinv(65537, tot)
>>> d
404446892183616504889
```

Finally, we have the private exponent, so the rest is just the same as RSA 1.

```
>>> pow(1215965040794194819807, d, 1335595887054866149081)
84270519872
```

The flag is `flag{84270519872}`.

## RSA 3 (90)

This challenge gives us two keys produced from the same modulus:

```
Ciphertext
==========

Here's the ciphertext and the public key used to encrypt it:

N = 24581743379972571392659557260552862968564735995376919071176116588018965991877078814651340543323238571730749904860256240486244468797552483047708032335984358019406165446960034756088512263106152612278422667192178578350229643355777184559102235227418410195188802704114664806841384836096383983831957450806767464479215809164169915193088379475330161034501441050579130532632347143211728214314397837877760173339478114085239306294306167605057943691830330780788767979116503898856363030884981340140445471089163376954187886339793049971982800570033811000703231680216782040242232239301043342912410825207760084320857218866380954105869
e = 65537
c = 10969762309443378678805473407871378084362123914209754514821346209619773698186764732448859512089399523700809754230316483884496527716646647949892505886895752131652608708076718614473187416240825150641246461053286773358034292139078545927806636239331207072254834126888177672115812978673796462390172016172912847684516554702523349807071573097093404261939087860472098643996806777574605138945124398501397274995020081562607651927889559147545572540824772106634108128874394203112805130537965654467704830970433438720197025216175040963527652750482186324999253023656151830943386858380087706395810912956580186166700309500089755016167

Another Modulus
===============

Here's a keypair that was generated from the same modulus...

N = 24581743379972571392659557260552862968564735995376919071176116588018965991877078814651340543323238571730749904860256240486244468797552483047708032335984358019406165446960034756088512263106152612278422667192178578350229643355777184559102235227418410195188802704114664806841384836096383983831957450806767464479215809164169915193088379475330161034501441050579130532632347143211728214314397837877760173339478114085239306294306167605057943691830330780788767979116503898856363030884981340140445471089163376954187886339793049971982800570033811000703231680216782040242232239301043342912410825207760084320857218866380954105869
e = 65543
d = 6347305203647312424658168638566996519536633843213752473347033201648276405512834045728137060482469364966071302654058810460143743648136005722951508769116446838265412691276743942328577903678631231560960365249689978487394328672065255961403143417128132281759689012776903516637682086051831660777993804028709893792486420529201338904946354402997237206877191874642011780225361363659104415691425670549400999579987644736336449881839189559406903440876008939785661820931169978522602730099426406938320762702254392482224971728733436757688084201290027030121578234794161328645466972334191813853370944034903463506523242021528072668199
```

What does having the same modulus mean for us? Well, that means p and q will be the same for both, so the plan is, if we can use the fact that we have a full keypair for the modulus to get \\(\phi(N)\\), we can calculate the modular inverse of 65537 and factor the ciphertext.

Unfortunately, this is pretty complicated. Suppose we don't have factoring at our disposal. How do we get the factors of \\(N\\)?

Let's go over what we have first. We know that \\(pq = N\\). If we can just find \\(p + q\\), we'll be able to use the quadratic formula to find the solutions to \\(f(x) = x^2 + (p + q)x + pq\\). If you're good at algebra you might notice that this is just an expansion of \\(f(x) = (x + p)(x + q)\\). So if we can solve this quadratic equation, the zeros should tell us what \\(p\\) and \\(q\\) are.

That just leads us to another question, though: how can we find \\(p + q\\)? Well, we can turn back to our old friend \\(\phi(N)\\). Recall that \\(\phi(N) = (p - 1)(q - 1)\\), which is equal to \\(pq - (p + q) + 1 = N - (p + q) + 1\\). There it is!

OK, now we have an equation that somehow relates \\(\phi(N)\\) with \\(p + q\\), but we don't know either of these quantities. It turns out, we can use \\(e\\) and \\(d\\), which we have, to estimate the value of \\(\phi(N)\\). This is where the knowledge of any keypair associated with the modulus is crucial. Recall that \\(ed \equiv 1 \mod \phi(N)\\). In regular non-modular arithmetic, this is read: \\(ed = 1 + k\phi(N)\\), for some unknown \\(k \in \mathbb{Z}\\). Great. We've introduced another unknown.

But that's ok, because we haven't introduced _more_ unknowns. We can express \\(\phi(N)\\) in terms of the other variables: \\(\phi(N) = \frac{ed - 1}{k}\\). Now we need to find \\(k\\). But this doesn't have to be exact! It turns out that since \\(\phi(N)\\) is usually very close to \\(N\\) for large \\(N\\), \\(k\\) should be really close to \\(\frac{ed}{N}\\) (shouldn't be off by more than 1).

Now we've expressed everything in terms of values we know! Let's backtrack. We can use \\(\frac{ed}{N}\\) to substitute for \\(k\\) in \\(\phi(N) = \frac{ed - 1}{k} = \frac{ed - 1}{\frac{ed}{N}}\\):

```
>>> from decimal import Decimal, getcontext
>>> getcontext().prec = 1000
>>> k = round(Decimal(e) * Decimal(d) / Decimal(N))
16924
>>> phi = (Decimal(e) * Decimal(d) - 1) / Decimal(k)
Decimal('24581743379972571392659557260552862968564735995376919071176116588018965991877078814651340543323238571730749904860256240486244468797552483047708032335984358019406165446960034756088512263106152612278422667192178578350229643355777184559102235227418410195188802704114664806841384836096383983831957450806767464478902000753098756549686770659161422728099254729358389158077928377352202831343837906217170273899263188309719920503745332149149531566138989242517822780033778888106059485872530429565017593346363722906078428386692014027957344765135443254269593609259850860518189657746391754631971861550441840499175895285807992607644')
```

I've used the built-in Decimal library to help with arithmetic on large integers. At this point, we can already decrypt the ciphertext, by simply finding the modular inverse of the public key, but I'm going to keep going and try to find the factors. We can solve for \\(p + q\\): \\(\phi(N) = N - (p + q) + 1\\), so \\(p + q = N - \phi(N) + 1\\).

```
>>> B = Decimal(N) - phi + 1
Decimal('313808411071158643401608816168738306402186321220741374554418765859525382970559931660589899440214925775519385790560835455908412125691341538270945199082725010750303545012450910575427877742799654048109457953101035944025455804898367746433638070956931179724042581554651588280438963657318243821681323580572961498226')
```

And of course, \\(pq\\) is just \\(N\\):

```
>>> C = Decimal(N)
```

At this point, `B` and `C` should be integers. If you were trying this method on another key and they aren't integral, check if you've set a high enough `getcontext().prec`. The rest is just solving the equation via the quadratic formula \\(f(x) = \frac{-b \pm \sqrt{b^2 - 4ac}}{2a}\\):

```
>>> p = (B + (B * B - 4 * C).sqrt()) / Decimal(2)
Decimal('163002265454828169651860238762995330849943819027754692796326100505820578640545617699466859378760005312043177075511227394922266181435491422912753650363606913354660344137977798164809150033027249153626586116283148829713331231184185509938565269837125121646111169141077309826502695188791957474586638431094589296083')
>>> q = (B - (B * B - 4 * C).sqrt()) / Decimal(2)
Decimal('150806145616330473749748577405742975552242502192986681758092665353704804330014313961123040061454920463476208715049608060986145944255850115358191548719118097395643200874473112410618727709772404894482871836817887114312124573714182236495072801119806058077931412413574278453936268468526286347094685149478372202143')
>>> p * q == N
True
```

Ok, back to the problem. Since we have \\(\phi(N)\\), we can now find the modular inverse of \\(e\\):

```
>>> d = modinv(65537, phi)
8593501725415438350507699717663711239037286821033623645264751318310306084195122644040417827915203914077898150209093042491727528336981017426889218744369403948649078483227815681168559812930482971449882382898820565613044713046435007330722970402908024413414874937119048558669804354483791651335489527372840523348278434155579987050213979928468610954475823200700826311865410639081989091183891088535355419767551442808855960734566875274564977306129520462262932964788652335404396430731122032924365138489075472717719194848215523038810606617849735880473177887021872271622629098808727611736471112806234234213903885391353692092005
```

And _finally_, we can decrypt the ciphertext now.

```
>>> m = pow(c, d, N)
42134526936715947510832575582794449340389855958782882560522796925
```

We also need to hex decode it:

```
>>> from binascii import unhexlify
>>> unhexlify(hex(m).strip("0x"))
b'flag{sharing_is_...caring?}'
```

## RSA 4 (120)

In this challenge, we're not given specific keys, but the source code for a service that continuously encrypts our flag with different keys. Let's see how the service generates these keys:

```py
from secret import flag, primes

p, q = random.sample(primes, 2)
N = p * q
e = 65537
```

What!? `random.sample(primes, 2)`?? Generating primes may be computationally expensive, but this is just lazy. If, for some reason, two \\(N\\)s shared a common factor, the prime factorization of both \\(N\\)s would be known.

That's exactly the approach we have to take. Let's generate a bunch of Ns. To do this, I'll just ping the server a bunch of times and filter out only the lines with `N = {...}` or `c = {...}` and store those in a file.

```bash
for i in {1..20}; do nc chal.mzhang.me 4001 | grep "[Nc] =" | cut -d" " -f 3; done > N.txt
```

Now let's try running gcd against some of these (remember, gcd is incredibly cheap and runs in about \\(O(log(a + b))\\)).

```py
from decimal import Decimal, getcontext
import sys

getcontext().prec = 1000
sys.setrecursionlimit(5000) # more than 4096

def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

s = set()
with open("N.txt") as f:
    for line in f:
        c = int(line, 16)
        N = int(next(f))
        for N2 in s:
            p = gcd(N, N2)
            if p != 1:
                # we found a common factor!
                q = Decimal(N) / Decimal(p)
                print(p, q)
                print(c)
                sys.exit(0)
        s.add(N)
```

We got some! In my case, I found these prime factors:

```
27040459658331988022372533430058221596925914573987753586001762832990849305442904741921265887297490445078024178492837096417088179303332807113633346082494163909989269052928168770766357959632074411936602375892507201208910271207942541505595899436293752394430565209842877361832162601046067483548654007689839878727510782529175905129593704704543813477177180010029097970297588309136535770910888033282029400584314336804379116250385511950262849262960276388184225623957991875351372626587857042100975022762165204840884234582558192024500393579978584424104740060359060260870750829892114696779089091594161267368630492355450903607931
32143563852534339785260597470053606965595930386333356887925707899281354258740110020256971299523685865451019868613505516638431041209931094846658969820051469136446928854615725163890340054536264028234544083927609734110836626806584536262427348056607404130673388276180563537974974783350798418165903207510381185848860038792106562811732076830435497422143874097840919779532954264313224249428142505183352793921928485039644477388693657122316329231779308745464896857173326202981868810310198787687596910953736317883922259687045038144889660391325001764218747100266598153715966091000823289176797333876605736133896251603647489764541
```

with this ciphertext:

```
353170509324772514696367678037962875757316768991923005798110297874375318970426571577797521383543061353561474773953358450251203264049925236982940954751659543130509378995798890190824330754053488546226641327923048938138888931760192257345199468280807362523513765367072494628537439959999738279550073074471797397693587091149679664779850601055309541738709403196377639604954855661447515267228441396889451262311019405084649162002112086547414666892596063628941910495879237669974546613427691134212401597520169724202692883706705799592452777890006989820752499196547901191482961940624877823805297164651213228979200974712291806557773396176512212382445233189196096145116301208032637800290814457485475608046392971170427176059840198740380204263955671764843632475720577037182384916094232225337301088738885353000289349355560320184761316578496140284805578949903069643035062401470877931209736332374498766551861270008104087142622001900917659144652500415988687066962648315199909328586666075426376965408786556555180885798977321871657688129020450160227595612800748441161087194084716319277623111102499734360226508264380596759996613516029537743429852378573160461142688755636072469395845657483917871581269876727519588370859416160737951855797158061399749198332514
```

Now we can just follow the usual method to solve the problem.

```
>>> tot = (p - 1) * (q - 1)
869176741629473154218411696154626074170579096708537156847589376727453530805794144999687234497615741375643801639337855758733108628412630183242284116918455261342767386881726988369475531428060313262483626295405398543447156417250335897967721292948140959547576571704072636415075656724218012570674818978256436517985513789582229297620321686445167443066921371972307536719533804054507284983712570794025619976877040653641139070068494160099767930940545477864849507439784159297295875173018316767217661279529862914171532589191958829426823667304803844126645256029951831675090862381036791102745050651912080129780931094901892081074882525654538561342632791668336833505236910599853153430657334649590556815604417113230980985834742448345211928737276759355206969478116773549658357262791941288986433311476550719468875758267660187213059254146594214590231906128999572341201409488814613252307549474268532246041705884387234936856889057645153197542514408305363168576479760419765276513368464149785102019410622437887184333128254457198375703743772860685725912153115514868666704708311659443052991115727294248900694220184377777646099045750683173629790630349923254173908143608728805730235058186456561786330037171766888229044002745995057927358590921574418832176802200
>>> d = modinv(65537, tot)
247701512175010606242844122390099503902893110597454086675350211165275334465413693732687771468208328145519314024412364496480740190317876831902835656982864472223306933255870957806684689572026221383392689447476793698154668971801951928930880732843926769633490816328439883276994187110154871611189001541982322426208331798038166174705200850477385176833863168352637256256934752251797191840346669586951134539391984501702176700362684673210299001269154338619128038366920193832424356632230085329833899319739677581335454997456981782156717360182062367773217471762079594125389810895991945731815147337012098823319933015845745737495393150917036433010304906388597693507138101824518323185748310713801407291225471083873461279467102319418702766269834109502680937011806872142255048882267499083790829835946832137380719174468851020287445377263163406104975224846595434832485751941995979854331875147335297263520163278799767870297330010980644922265308781358915847528921257997161238223296501288211794107397839316301004650652858820164091475331834623480282937291663311887973023541467214907882581062124275976726402886161765472223266122609907527562805737263614700370875725135117992960062257682659401627832920400034944709917372465736144420850457034076100836604759673
>>> m = pow(c, d, p * q)
13040004482825872529226782655247636467967042494451086101828216991918469172926217568750157693
```

Decoded, the flag is `flag{generating_primes_isn't_so_hard?}`.

## RSA 5 (150)

In this challenge, we're given two files: `key.pem` and `flag.enc.txt`. Judging from the first line, `key.pem` is the public key. So now we have no private key, no factors, no known keypair, no oracle. What do we do?

Well, let's first look at that key. It's **HUGE**! Unnaturally so.. in fact, this key is a 16384-bit key.

```py
>>> from Crypto.PublicKey import RSA
>>> with open("key.pem") as f:
...   data = f.read()
>>> k = RSA.importKey(data)
<_RSAobj @0x7feecbcc9ac8 n(16384),e>
```

Wait. Look at the public exponent:

```
>>> k.e
101
```

That's tiny. Usually you'd go for a public exponent of 65537, for a nice balance between not too computationally expensive and not too insecure. Why would a low public exponent be insecure? Well, remember that encryption formula for RSA? \\(c = m^e \mod N\\). This depends on the fact that discrete logarithms is hard. That is, if \\(m^e\\) were greater than \\(N\\) and got wrapped around, then it would be computationally difficult to determine \\(e\\) without knowing it. In fact, the computation has complexity \\(O(N)\\), but \\(N\\) is huge.

But what if \\(m^e\\) _isn't_ greater than \\(N\\)? Well, if it's not, then we can just find \\(\sqrt\[101\]{c}\\) and it should be equal to \\(m\\). We can't use floats for this, since it would be too big, but we have our trusty old **binary search** to help us. I'm using the implementation found [here][5], modified to use the Decimal library.

```py
from decimal import Decimal, getcontext
getcontext().prec = 10000

def iroot(k, n):
    hi = Decimal(1)
    while pow(hi, k) < n:
        hi *= 2
    lo = hi // 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        midToK = getcontext().power(mid, k)
        if midToK < n:
            lo = mid
        elif n < midToK:
            hi = mid
        else:
            return mid
    if pow(hi, k) == n:
        return hi
    else:
        return lo
```

Running this gives me:

```
>>> iroot(k.e, c)
2077392566272321951928260001757565
```

Decoded from hex, the flag is `flag{too_easy}`.

[1]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
[2]: https://factordb.com
[3]: https://en.wikipedia.org/wiki/Euler%27s_totient_function
[4]: https://stackoverflow.com/a/9758173
[5]: https://stackoverflow.com/a/15979957
