"""Source-bound installed Tier-6 specimens for native replay.

This generated module only decodes reviewed inputs. It does not register them
or claim Tier-6 conformance by itself.
"""
from __future__ import annotations

import base64
import binascii
import json
import zlib
from typing import Any

from verifier.runtime import core_obligation_union


CASE_REGISTRY_SCHEMA = "verifier-self-polish-native-tier6-case-registry-1"
CASE_REGISTRY_ENTRY_COUNT = 26
CASE_REGISTRY_DIGEST = "sha256:223d9f4955d8e32826b3804790135726514b7448418d2627cc8c638b1a4dccd9"
MAX_ENCODED_PAYLOAD_BYTES = 16384
MAX_COMPRESSED_PAYLOAD_BYTES = 16384
MAX_DECOMPRESSED_PAYLOAD_BYTES = 262144
_PAYLOAD_B85 = (
    b'c-rmVTT>gy)&}7J!gZYL^FdYn!eD`6+Yp2hhg~VEk48ouwh%ZZmH+;&83{}x<x`Ym7hJq9BZe7GPxo5gEvcW9^xN'
    b'9|js9M*)84)_Kiaj<Z)@>xILc*w7IL_ml<`_;ZGG=>_e1x?S$DAgp}V`$JzGENcMsNnSWD+6T@0_joL!c59<GMBm'
    b'vry@G9K1p8UL8CFT?Qa_Q!O6H5rFAx&85GJiHI-;jBIH_Q!E)H_raJ`z)35gi1(ZQs^4xewfQuDrYg=7Nh6_<zeU'
    b'k<nm^8B747Xf4zzH_c$Esi|w!1!~MhE!#>|0e%g4tPYp-=!@c3oIc?vk;r8wJrT=z%ymKBe+w<-A)y^n=q#rT3%U'
    b'hc)9QnJZ-0jPA9*;Kfwnyxi?sFfTvOW$bCr4_yH@Y1@ZXX{v$Jfux(J%KW&9$y>ho_e#l|K$1P7k)t_QmFhLDwH_'
    b'UvdBGBb_Hkcc&Ze{*S#weYidRHjHBDzo$pL>{yK2cAOmLQM}r3+mW^g4=2>V^ssHHt+fB7z5eNu7H!=w&(G7P9wq'
    b'sCTCc6mhj=;oH9hQPI)4&HZxrczM-PwNJGmZw8>X#I9k={>Qx_`tG8~_?e7rN7#xZa9NBhG{ZTmxf2Rk1QHrf~t!'
    b'{y*>-t;$ZTP`;rPQ;h_`pTuTIoM}k=C5-x*lYGL$Yay)uVG_B9xr?6d8<2(4dwCVpl!dP``pkqN0j>}2G9Qf8*!M'
    b'`W4?ZVao#RHYxm3bQM%l`JN@{%ZS!M3o4P%2AJetl9JYOp`rfdu@2}yAwf9S6G}#_epV`>?c5*zrjbig++RoFP^0'
    b'CL$<zW+#jXqzHC+0u*y94TXqodxzqI~V%$E{zQxZY$cXF)%Eh~k$~vwbw%{u_1q&}YAV?$H=L7@Tg-_xIlVpxa%P'
    b'(~Fbi-uZmoCd;nZ-5>PU=dUx^8w?k<xry<7zggA?Xp9~$xW>_6jos7Z)4v+KlT(^cC`VV*oX_gFG0i*G;cGJ{DBi'
    b'Q}c0bKWeAM3ms&^BQ4*$k{GppNNo%6x|V10XGo#oDX+WPVrb>`HjonN2#(*-db#jOF|S5ujjn|RsgmFAF>xxRVO-'
    b'8|@R=Jmsi!$p1J`s8@$B8$zYEi32hdD)Au+rJp}4<8owjqh{l>T}pRT~BWw^3U_v+#KxgAF74z%t!n@{)7JbSmyk'
    b'-M*F?N!pFYra=boT_}F(jx@dA1j(d8V-)Dcfk1hQEbZc-sJvQ53J`Zdk4c0dghdaI={6fc``om7IOJlP;Iy_o9Cq'
    b'29N!Z~!8MY%njL#Nx#9GWiu?QGoq-FfO+J?84T+h@Ja{=&z&S^F2&?RckoOls;t{b=`k8ao;j&2}5R*><~s;p5bT'
    b'$Mu0|;xU_pN4Xh$)4AgL7-^0@`+GWPP~C3g^zm-Cz5KDRf9Sit!*6r_s?T=*-OTBW=8ea{|H0h-)BeTH=Kg}mu0G'
    b'Fuf6<Tcv(SIhk2k;OE&ni$^=!M1;o}_J#$s09{@<8G{V~lI^Uv8vJDdA#uyeS%zo>o>6pK+fUSIeepm|<)`Z1rk?'
    b'H~Q|@3tSy!9T0(vpW4bmWLPq^TNmf=K1W_;p%hUXy>PXcYba?WTV|h{iA&jvmh4Je&4op`q)41@6F?L+t-`1(8T1'
    b'iyxAD|9uqo7<KZD3o!*=tPv?Z^e=m>O?oNMx?Dr45n;#a(Yxf(?Iir8j&u3-MUF-1RkZ&%ES>75={>ft>&1buduG'
    b'43e&Hke2Lsz}~K(BfJL7Qe}&R^^BVsqy&u0?%pboalSJKMSO<Mj2<<MXfOeV})+e>mEkALFN+hZm!*gF_nsi}LfV'
    b'pRGQAo|R44ZO6UXy{6|_=g0DNl&*GfqEJmNpS@1uUn$2A&11o*<MoGdd`honFD57Ad~_lvzkWIzh;Y<vVl?{H?+)'
    b'w!zy3upoUh84Fd5#LXD{SGzyGwk*ZchZrF^fuzP<Z_?tXJU8m5PK0pR-XD&MYk{`1>f$d|*(q~x>fcw5Hw%D&mXH'
    b'ZCDkc|ZT~{rLELRGMS7uRZ;2nCW`$;m*bIDmRM-*H?Ks8D3vC_xsP<&E5Fs`nGw6KfJoVDQQCG{bwzW3%%N(48w>'
    b'H<dQ~#cDx&x`(gRE_A`}Uhh>z{uEJ%Z^4pSs|KWw|c^$t}HJUyDlgfTC{^e?XQ^ujm)&Hi#kEOp@eQ(0U=sNt5;`'
    b'><m?>{%ipOsmChIv+-JiJXKx=222PiyNx>zdCq|174DCDO^|m&rJs(cr&28{a)O@G|`Je6{K<K1`ZJPC93pqvMau'
    b'VrO~yrQA-ambd3YXwzXqgvv#ZJQ$~B2v(@<vkzM6%5_xChZwjj!t3NrDJ&WnJa^jZ!hKkKUU(bfr)9TvHy%^e-c1'
    b'|zW4#-VC}!z;oZrnta5pYL^0wL2R5pV?q{;PoTGA}3KRk<n8?3nu{P2{w&QsogSZg{!lW}@1ry{BItlg&bav9E=P'
    b'D2@gR@Zlrb)BsMzMHN9zMIZP@0vPJ#&@?9>QvX0whp&tL|36Y)Zx`|Ql7QwU32~6Ww~nV^=&vgKX3ZRQ>uTadW_3'
    b'|@7gT<Mjd3-6hzgTPmOd&M{6=Gt~g_yP{sxpl&LHhFI4i`QTB?mv0BAKwvt<2n9Ppi#oFFY(H>qk3z(g??~AL?7B'
    b'k1Ce!rr3Iv9HBkVVEyDX&5>Mpux+InQ$~*(;f?DuphmwXUA3X1x=}(rs=E9u29x-!?64`{eZ{rKKHTXKjC;jWo`h'
    b'f75>ZeO-0hX%(l7Ff~0m?K`xWsyEy77sbrR$ih;nk!8H#8oxh{xVhLz=D4QQoK@CSKabRKp=lIUuL4WSNn3nmRX0'
    b'0g$RaShUk%pT%)I+PmfMj%3;xri+x+!Jv@FnNDp#ylsUlZ4TQ9Zb(o!8HB{f$ceKoQOr<LPXG42_S%8*l2^7#5G)'
    b'_*SEcpf+xf>%kSokdkEWlqqRw^H%MB85`9L|dWIU^mo{tTRGuWrC^AC|`N(%sP2Hcy8%b8o%lPJAE22`ZXGUnI?F'
    b'8>fO_v*qKfa&0wVQbvp@{H?&VMVcs$SPPjgo9meSYX*1aGt}d>wzg<0h*71J*pu5|Dddkt<>HQY%>9n_C2e1R!0q'
    b'g*F06Tykzz$#sumjiu>;QHEJAfU)4qykc1K0uV0CrfB9iA3f!4AvV!6eI+<KBy4WYR%arDL=ymCB1sOnF1uVYX1o'
    b'HAI)9PKq{5P$3oL=h>kN{;RP=(3;1bv=qD~W;rFy2^}4a-iW3tAq7oS0OOG}Ws~)a2D_(jmQqY6y%~1+Lic=8cIa'
    b'(<>@+t(2cQGc0q6j906G92fDS+hpaakW=m2y8IshGj4nPN>1JD8J0CZRp9Uj+KVGhg8L1?KMFEYs#M6}5lS#xB{W'
    b'>1HbPBxbkObL=UOLYxEH1CNhItEF{=FNd(|7zqQvQ)}M?;_Q@*eWg4l9`;j&RIKC15e5OMj14du_#?4<25_xlS$g'
    b'X8FCn>^OqEdb=vsYX>VZ;Fb9|e%mL;AbAUO(9AFMG2bcrQ0p<X6fH}Y%U=A<`m;=lK=CGPMd|zAzIxIzpYQ1vNDv'
    b'_jWqM)6~DLW^NH<Sw#Y}A2KTsUQd(}3_?c#~+qpaifvbZCSBYU<!sOj<-yW#rn^bAzC(W46?g6^~i^k^-~F8?Ot^'
    b'1yUL1eU{Z~7mO5d=JS;zCGln1VXxnzACLpc0ptL306BmhKn@@WkORm8<N$I2Ie;8M4j>1R1IPj70CE61tVj-f_++'
    b'KO2M$_LGriW*rXX$b(hD1$mQqVmoi##>5@@t=lar$pT=kZsBP%zFj?RCw5{3TNxIr1NlTccwDyX#LoaJ0sQK%?ki'
    b'_59dJRuktN|q+sj2cG&ee-<}F1;OYxPH-3RodA5^r^ei-yU>3-#0-Ipa;+c=mGQqdH_9u9zYME2haoP0rUWR06l;'
    b'nKo6h?&;#fJ^spK|{Aq<10<laWVrITt&p0=>7%!QpKUo%Di7cBI^T=YhCFoj>XMyXIqX~vnI!tn5P9VN#;ME`^>K'
    b'eQ=mf4`VOu-aWA}f~XPy$6LCzl<MPO+S*XQ`yB_kqVyo$y7-w*nE5<L17+q(^*s-+$j}ZeS2F2p9wm0tNwtfI+|@'
    b'U=T0}7z7Lg1_6VBLBJqj5HJWB1PlTOv6?|Vt*t^ImcIYN=_sk4$tk)c*C`cYq{+%wN(J{Khn%d5tk%f6w>4!J0_T'
    b'odouZo8hbH!~<_<E&=uH*UQf(uboT{!<^R?2t7OQoRS%sjD%*Ga76i?Zg7+KDW+m!WNafcix;U&ePyF2L654-{10'
    b'B?Xdz#HHV@CJATyaC<-Z-6(z8{iG_26zL!0p0*_fH%M!R`Z6(rB!glGH&pa$zYYuHF2q}_Az9gY-HToLW4m%W|fY'
    b'{E6NKc$!k-k;>>4NYI13g8z}UzrVTkNC#4H9S{mzA?~-z?)GDo_PDUEbJRQ{~3NL(cQ5sQ_R&<UPu9~-^4dv?oMX'
    b'_N(dphkczyaU@Z~!;}8~_dg2Y>^>0pI{|05|{~01f~LfCIn*-~ey{H~<`01c#@^Rgl9na**1~LT!)S7p-KBItiV;'
    b'RlJEvWVCH$P};FnSq`Qe&J@KY8XuBYah@ES;J+F=u$*~zK2Z`~4TVas%xld`Re~ArW69d`D4o*AM_Y9Wj2Y{ht;y'
    b'0I-wZn3(>-639kzP!fBM*IZ@~^=2e1R!0qg*F06Tykzz$#sumjiu>;QHEJAfU)4qykc1K0uVuo^pjUt9${EPtm%('
    b'UBz^Z7i%(NHULw#si&|jd0D^GJC@~9gCEqq?OiQJDDgbG>k%-V}~~Quf`5lM&^7Ci76F?p;^I2>vPc}IF$lrI7N|'
    b'*U|E@%g)qT!rd6_>QHOXtUoHJ*9B$5Ek{v$2?|nFW-|KcBH-Hbo2jBzn0r&uX06qX8fDgb2-~;dh_yBwWJ^&wp55'
    b'NcD1MmU(uo^!6VSN?;u*@H9q{a!Qq<5(@NB7r8B~ItC1|(7mo^qlXk4gG0s!hp6Cs?I1WULZ%{_q(8S0e~jtBKxg'
    b'?u(*i@|?M?Nje(nMsh7_9^fIQLPwPG(gY!cFftm-F_$L26@oYq<NS>#fEQMX-R{9bXZ9Ng0fT@+z#w1{FbEg~3<3'
    b'rLgMdN6AYc$M2p9wm0tNwtfI+|@U=S-C#MAOB2x94XONSJL;7Y|DYAA*CY6KTXhT@vfTWa1lAWE((%4C~&K2VafE'
    b'<sUbq_cSuK{VliHGwcP3So`6j?u}idGCg$(N4LetQN~N<IFqW5R0<3Pt@d_Z_O6fIhq09l0aOQ+uIifh{MnCcRTG'
    b'Z@B#P$d;mTGAAk?Q2jBzn0r&uX06qX8fDgb2-~;dh_yBwWJ^&w9#D}NFRnWsSdf-`EQ&VQ4#9|YVMJQjjD?t`py>'
    b'o(PE={3mMV5=FF;g_pbZ+7)wqMQsCwgdt|7!3+<q1`-Q(Pq_Q<UBq;i6Jmgj}T*I*6J>OeM)cEtkOw&Sg%e2nvOJ'
    b'Gw^Un<-906ocz@7b=q671K0uV0CoU7fE~aNU<a@R*a7SSb^tqo9l#D?2e1R!0qg*F06VP64o{1#V25SwP>mN-`)X'
    b'pUK2yNC4b_Xnl9y33A$;UE7bkocED7&xvXml<T~eNFH_r}D@L%u!4mk-EZK|AQ%AlyOD(xBV5S&vpBMZzc%VUm$O'
    b'Ba)m)>R!eHDA;>#10QP?S$}R?9goWxBDlZ#|_{E@B#P$d;mTGAAk?Q2jBzn0r&uX06qX8fDgb2-~;dh_yBwWKCFf'
    b'he^_6IKP>YH7Lt@KrJ$>+rNjmqSe4b6oD8E8kZs~3%FHacF{tWIjLb@Dq|Ow!Ie&PJ|Em#1;IX*qO|^w(o0DojSx'
    b'H50lv6%Ar*twYi$r~l#gvQjrKyEUwMb5V;H?nEu$>Gh4=<?@pZ7j=KXuw$_yha_{s4b~KfoX05AX;01N;I00Dpi#'
    b'z#rfb@CWz<`~m&|e}F%%<`3T&SAh>pzwV(>*)nIzvQRNLOYjsBLw(;CrK{6X22r?FwRszaiA?h>3#GxNh7QUcKD5'
    b'DqJ$cYoSD`3Jib<+{id8$Qj4Lr(+Hjr*ez7$$X@t(TGH+`vs?z+ynU-%w9xktQ8NDPs?5*!~H~O9FFTexf0q_8L0'
    b'6YL501to%zysg`@BnxKJOCa54}b^21K<Jh0C)gAtOgIyR#zbpOW*dON-#V%3;f0DY@6>yNG>Joe5S;d=#8sM)+AK'
    b'nOfZpaVu2e9zS1Vl%fmGKuSO5d7blV_iRT!dDpY-8D|1|G%S}$DslTEIGjCMZN$0?_5P?M>r1ko((8KgTFKQ1*yW'
    b'L)=y@fnL9v}~p2gn2D0rCKOfIL7RAP<lS$OGg7@&I{&JU|{G50D4Q!;13ow73d*SPBo3qVJ6>BFhwMEQp+n)kdZo'
    b'40lp7XPOpME`*IVaBMJI*kVm$y0o88^e1>|g8ypn5VN3DIrCE5925Oh+PT<dkk=r*G}Z^NqIH^4u2VGCXDV1_7Ie'
    b'vP=EIh*zg@lT_dWEw8{O@n`kmQt&;#fJ^Z<GQJ%AoS51<Fo1Ly(t0D1sDfF3{(pa;+c=mGQqdH_AFMi0-ISAh@9@'
    b'PWtL^l+h5RwYzss+E;x3Wk+Q8<7m7G2xAi$~xhBjfR3RqU97R%flQ#%)<X_{7^L4R?`?~%$X>8a+-3?DXEOgh@AR'
    b'ZvbH3vIHldu4l7KJ%)8)HkZ*<`XbLIAn-_iGLvQa>x6|B!9zYME2haoP0rUWR06l;nKo6h?&;#fJ^Z<GQJ%AoS51'
    b'<Fo1L$EzdU#x0g*z;BhgcYwj&sMV<t6YStFyJ5m~|*w7ZW{mi3{&ysj_m(tg$Kz6Qzhbvw3%**uNe+G@qJ8JxS_B'
    b'm29$HQ=tCBlW0C%NlI0tQQix$c#2K-Ws=m}ER)gd=-v!EGz0nt#o=K4bBBK54e$nd1H1v=0B?Xdz#HHV@CJATyaC'
    b'<-Z-6(z8{iG_26zL!0p75hH#{z_f*Y1{gS65`A!4XW)yzYdJjld_;WS)Q^j2kCg4Gli9y5!Pmn;K|oYhJLXO0^v^'
    b'slB3Jo;!<$T?|I8IwU&=S?UnL@L`BkyTUqXhqQ?YD&HdHPV!zb(GPUx1tTV!^;=NhM(SVbUW=WzyaU@Z~!;}8~_d'
    b'g2Y>^>0pI{|05|{~01f~LfCIn*-~ey{H~<`01c#@^Rgl9na`28Z?|s%*X3nzk#_O7$<|Q^CMMVA56qh+~7Vur<(O'
    b'aLGRL&-AX=LPia%h78dSB}xY9kAYWvZzO)*H=)i6x3?ya~xDC4x(qSDBdc&O7=|ovUVLN)qYKpu<f_FZv#b{`Ti?'
    b'r?~+-03Co1KnI`$&;jTGbO1U49e@r%2cQGc0q6j906G92fDS+hpu=kD@U*rHb692$s_>YFRP@p=I-`8aT<Mx9424'
    b'VT{wx<B0%wIg!-Y`R3z3xY6qVovpErjl_OC_`l?kDX7D{JXVm3-pl}lzhXd?>!P(Rb!#8_q3&IV<f$SN`Bt*fr^w'
    b'?YmLHN2=e?ESmD+i7oM4loCp1Iz*D0CRvjz#L!>Fb9|e%mL;AbAUO(9AFMG2bcrQ0p_rxIXo?{0v(p2gJsMyE~RX'
    b'~K-t#dV_;I%5_OV73RWV;B3K==$)%d8OTz)yTBB?ZqRgX16Z}_G2VJDIg+?}=5~x*`hIHmZc*`3iNz}bU7D{WYlc'
    b'l;yr4>_|dEuCo!oL}HxW1rq^^)w+d%wNgX>Y*}U<a@R*a7SSb^tqo9l#D?2e1R!0qg*F06Tykzz$#sumjiu?64v`'
    b'JT0z*9hR{}a=}U?LpG6D<%^9*8E?EYp_rguu2GpJm5|0qRx*X#an5q$TGr^|JUcYOe>HYcCcD6lE~?gQX;dfSSPj'
    b'nD%(a%Du4sg3!bT-ko7_rWiMdh~b-1YC3_Fa&@I~2S(Cuw+Zg+c~#|_{E@B#P$d;mTGAAk?Q2jBzn0r&uX06qX8f'
    b'Dgb2-~;dh_yBwWKCFfhe^_6IKP>YHop{zImej1<=aQqLq2Xe#p$4n8&eeJ6tEMPO>#eV*I-aFr($iUO`2Xk+kMV!'
    b'K&s)-!(p0z=j!ueBQtFg0l`+E@l~-jgAyKcg)YXzpf~Elzf;QBCC)*ai34(Y$>E#sS_x}Ty;5zU'
)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("NATIVE_CASE_REGISTRY_DUPLICATE_KEY")
        value[key] = item
    return value


def _bounded_decompress(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_COMPRESSED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    decoder = zlib.decompressobj()
    output = bytearray()
    offset = 0
    try:
        while offset < len(raw):
            chunk = raw[offset:offset + 64 * 1024]
            offset += len(chunk)
            while chunk:
                remaining = MAX_DECOMPRESSED_PAYLOAD_BYTES - len(output)
                if remaining <= 0:
                    raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
                output.extend(decoder.decompress(chunk, remaining + 1))
                if len(output) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
                    raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
                chunk = decoder.unconsumed_tail
        remaining = MAX_DECOMPRESSED_PAYLOAD_BYTES - len(output)
        output.extend(decoder.flush(remaining + 1))
    except zlib.error as exc:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID") from exc
    if len(output) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID")
    return bytes(output)


def installed_case_inputs() -> dict[str, dict[str, Any]]:
    if not _PAYLOAD_B85 or len(_PAYLOAD_B85) > MAX_ENCODED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    try:
        compressed = base64.b85decode(_PAYLOAD_B85)
        raw = _bounded_decompress(compressed)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID") from exc
    if (
        type(value) is not dict
        or len(value) != CASE_REGISTRY_ENTRY_COUNT
        or core_obligation_union.bytes_digest(raw) != CASE_REGISTRY_DIGEST
        or json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") != raw
        or not all(
            type(identifier) is str
            and bool(identifier)
            and type(item) is dict
            and set(item) == {"builder_adapter", "checking_mechanism", "evidence_base64", "negative_adapter", "policy", "request", "unknown_adapter"}
            and type(item["checking_mechanism"]) is str
            and bool(item["checking_mechanism"])
            and type(item["request"]) is dict
            and type(item["policy"]) is dict
            and type(item["evidence_base64"]) is str
            and type(item["builder_adapter"]) is str
            and bool(item["builder_adapter"])
            and type(item["negative_adapter"]) is str
            and bool(item["negative_adapter"])
            and type(item["unknown_adapter"]) is str
            and bool(item["unknown_adapter"])
            for identifier, item in value.items()
        )
    ):
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID")
    return value


__all__ = [
    "CASE_REGISTRY_DIGEST", "CASE_REGISTRY_ENTRY_COUNT",
    "CASE_REGISTRY_SCHEMA", "MAX_COMPRESSED_PAYLOAD_BYTES",
    "MAX_DECOMPRESSED_PAYLOAD_BYTES", "MAX_ENCODED_PAYLOAD_BYTES",
    "installed_case_inputs",
]
