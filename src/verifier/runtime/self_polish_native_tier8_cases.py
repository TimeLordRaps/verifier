"""Source-bound installed Tier-8 specimens for native replay.

This generated module only decodes reviewed inputs. It does not register them
or claim Tier-8 conformance by itself.
"""
from __future__ import annotations

import base64
import binascii
import json
import zlib
from typing import Any

from verifier.runtime import core_obligation_union


CASE_REGISTRY_SCHEMA = "verifier-self-polish-native-tier8-case-registry-1"
CASE_REGISTRY_ENTRY_COUNT = 26
CASE_REGISTRY_DIGEST = "sha256:89172adc41b921b82fb7215d75aba80a12345751ae1f9129fbe6400220b768bb"
MAX_ENCODED_PAYLOAD_BYTES = 32768
MAX_COMPRESSED_PAYLOAD_BYTES = 32768
MAX_DECOMPRESSED_PAYLOAD_BYTES = 262144
_PAYLOAD_B85 = (
    b'c-rl~>5|(<wl(@L`rX};BL+o$KdKCpO<rfBNr8lb8#f$40w9S&^08!-#EJ9ncWsm;y9djk6xLCx0`687iv%&`9<b'
    b'NK9{&5;-FHd6dp`aAYw$Pz?D>B`D}O%sRsGWsMOFOxw*Kka^Jn+*-bRb)hs9wXE$nxTAMUec@#5KEp1D))y7Q~!4'
    b'@2!v#jEq10bBo4|8#E7^-q7RUJu3j)tkS$*RS6GRJgZq{`R_TYxnkt<7;g5s(9t<zx`BC`}oaUKe+m*x7dLz-qtu'
    b'o{mZ$k>Fu(3Q+o>guWy?!PwkIR^uLs^%sKAg`s?9sUmwCB^Y7N)`c?i*wc5Wm->u)QU)`VT^!iJdZqM<nH|H$1tV'
    b'qM3*X`?b(k<=oV7J@7UA|<?MY8Yr>+@yWrj(nepzoYFr%djCac6d+&+^rwEneCmOQGL?{_DBC-{$4%QoP*sj)$iT'
    b'=VRLS<@@h8KRRi7p6;6LCBD}#l=<#*E{EmY{H49%nEgx9cXVD(9Nu7`EKj#@fBQM@+pWSkMQZg+vHLL>hq0Qj*S^'
    b'k@HMi~Si)r^PPRtd5GdnJr8Sr=HE>;+2qPv@o?oU~J6lP_l71=dUG8`w9d2)A&BYV!;zBOXmnsnEiXu-{3+v&K&p'
    b'~aeX|M|E-o=mj9nq+%3!U#Jq+ictnS+c#D@u=eDZnWceG)dmt(VnuTKUvy8j%nM4He#V{avJhvi|zK<kGYsAyH3X'
    b'y_H~}}(@UB6?iH=OqBR%!%gvAZ(D&}l+v?@!mZzG1pN8iG=UIKnUzN1|pikvs`|s0TpNW1XxqqK5&X9#D<*ui--X'
    b'89^`z}m(FE%0GA2V_4%XHaP!{PQI(@CGOuYM@f!|nUja`$S}m#-ijvH35O)Awoh3vCZs{hW#YTbzr?p>vLO@CE6h'
    b'#hU3;_4mUqe}VnAki}q!IH7-=lZ`rQS8JXRhqGDbkik}(WC2+^mW}sknBFB`Wjc<qW`h|`<V2iwR~zlMZJo~BPG$'
    b'o>Pcvp)bG1W0nD$OWepvtgC126|TOF^q+C;X`S2>Q0H5s!@2K_K;-kSuv&}J%*s=<y&osAvK+xzqS6?+4F`ze3fz'
    b't{I^?cS~9C41SwDa8_c`y*^{*;cD}Yu4%eWPeEZi)FMsg!j7z-yFyur)|R9dtHC9we`a~4Zq6i{pY{hn|im+LAh0'
    b'bgH61%qxFsK2-}QRdVqc|8NPRoqdRO1`KO1`t(I;6!8h2x#6GLlq5D4l&F7Px?tdv)eG5O*6=~HwIbH8qtQI$$WF'
    b'B;!Lsp|n@pt5~{+r%LN33(z;&_nP7IwN;w!Md*SA$9S!mbX36?^FOam<D_))o3cF1u{JyV_*aW;Z(S2G<?l^5uU%'
    b'ZkF8LpbyNn7XNeCOqg3f;P1#lUL9oYm>Cx$8{L?t3!Nng?0+%Y5OnMmM|+i%oJYs8AL!4Wc&C?bu{ylX4k6jo_}('
    b'v)E*EM3WBzjeHj}V};qWtT>X&TzvCri8Z7!zmf6h{kb>qMFf0NBtL&zpQ@0Q#Ba`TTvw?8*8{w!O@xeSLlrM!Qyg'
    b'E;T%=j`Q<yJ3(0!S5xV&f4YKB=99sf67<8AzvAhudqe~d`nCAb~u^w)aJ<={%Xy$baOJvTEWf~)^N<)OxkF9vLc7'
    b'S+$uZnPIlNro(rBQ?qXKh_h^(QxsKH-$8X3+Sh4J}&X+tow5Gj3nRauIBcm<0HSH2szsGlA$L;ZA&YSS%i(h@~gA'
    b'Kj?u^cA(-*5TuANw=u{JXVS{s$d?Y56<3&|1Lf9Bz<H=Wc7Smh9i|e`HVPYKb*|u;nbh@*KYJPn3@+;BTkb@8nah'
    b'maKYdrsEglpg-K_<c@se_;6oa>T(sH==$JqPPljelEaUfq~q8}U;q97N37HM&c1K(Z(r43q2oW%z5Ji!f!zohmM{'
    b'OTwR~yWq}Mmt)hqUA*(>f{IrJyI<S*E}du;y-_b$k2Gu;zy3J-((5#6iJm~q@U1o@Rb$)V?a*wz6)1)mHV*2E#+z'
    b'&$)NbdQ1V;hr+xTi{ctm|}@L*0P1p4|%#ooKSW7YA>_Ic6ke%!M!OP4Ku4<Z->Rzh^@ARfj#azx<A?Wc(v^g_p<|'
    b'Se~Xj8wX6M@M{5E9c5Ys>|AQd$Redbpo`0!-6SJ=3!(wOeC|X_H!`=7m=!X~UmAy;$y9K`S<LmzHZWQiTwL8B#zk'
    b'c;YSKr<|d;b6a_cMg5uYdaCTwyQM%fB*w0iQm+^~>wG_4Lk<KbP1CeGTshMG(}os(i)5hKIVTw5Uo^NmmxS@`Wor'
    b'pM_<^t59*l%SQSt2pBIFYrICgXaDn;|8QXbZwKc8c3>_;-)D6Z_!akcqrF0E<#|pj=hx1;GN^(g#DVHs`i0O{<FQ'
    b'7ULF2+whU(e>{C|IWHWb(2hTT7ux3@LcLh(>ZrXD_j^R{^V^P3-vWBtRM8X<j!4Ftny??e9|s`Iga^A_jy=7i&T&'
    b'wcJZFDPrJoobk@9oM>0jUOtlDjhggmd^3Is;asS8((^XWLo-FQI!p=J^k#rJAYV$_t3)q{L@eMtG9oB02F_FRSfl'
    b';9}8Fi^*7Lhmg>U?58r=N_t?Cy{`%ql532Al8@$txzdZY|pI`s<GhmJQ%d?+=MMzVyFn@XW2DoJ?e!$Tl-uiHEfB'
    b'olk`^_1>+vz03cdI$c@V|eR@x$ByD&x9Rp$MEOf{Hugyt=4ECS?#Z9fsQDBGjSqWucuXn^1bvb6j~`6)y0xo*c^c'
    b'?3bcHS3fjAy~ee0#@@g2^Q*V#{@HWM*#FQ4{@2fw1SeH|xGZ~T7BBvB2Q#{h%sL^^_xklu)%g{{v**u#MUDj3ivH'
    b'(<zW2l1^H7s|u-^c<pX%mU-Ef?%y5YWndIS~JLI!22Lhc+3@Lnk^T{l6^{Ms)XPcc{3g<uj2>FGeR;Qvy#?*QjNZ'
    b'}8^l>D^yH286BNU(2rw@vrL4gjS*Cg-||M0;laW-vx{b#fmcUnDhOH1ESWAUo#fSvJ9Op9IqVXS~y30{^|9Puiu='
    b'fCHmLhbJ&HfMB#-TAu+21S#vB#QOH0BL0Q#4+(e~nrep&@;~Fef=t69%cu@)O8OhH<H2=2ef(fj)kj{feI?)u0VU'
    b'N%tUrFvcC{7W=Nja#6$3s~JI%sMoea*R~x1N2Tw!hP+2X)7{p=s{_Vh^vO_{T|$-u!ja+@D`{uU=nX{l>T7-M?7a'
    b'<O3Z+8{Mt&&hzQ#%wx<v#%J;vhyxLCjMdo!OPS;jaXaD@#3_jHS)AfLfV~i>Aja9sI6a(!&3N8!5Dx*j1Ak`8W-z'
    b'M-@aL(`MqmrXl24Y$z&RnF)`;&qJ8sT-vLpTiahijEtbu`ceLVf1FehZTkapOdO}aVT)uxSCyUq%GvV_sv&5*U&U'
    b'vj{@?QeN<IvJ6vIO!n&^(9X3u88?YGv<gV?+1$i;$)A1r_QFfv&r%VOgtSUPBUP%Bfi(SnXtfGcbA#RcmzDg=#)v'
    b'E%vvYSxPVMy6|1#E%&$lXY(%okPp}`7U7x|ufJJUuas+N)_Q3DAoG^8ARK$VUw(1{z<5T1@u$IGe0Peb&aed9i_C'
    b'j_AJPf~RVIx~+qr8h(20msB|93cHjYpCPaM740du-p`;;4t6Ev|NjH6F~>3~QFJwpf3xXWL=>t+cC!z%fSJEA)am'
    b'A_+Sj$XDmlsf(jE>=qcWJ#~;D&&ifohQr=)40AEJkMkHic8DKrX67+w9%JS)W*%eaF=ig)vGEumkmINE7<I@sFgP'
    b'nk0X1yuTFZ)+Md%6+6&9W@0JEJ|&TGP2Dr|?hs<PAq7wy;O7vVAJTD}^O;e|otRdwJ)nl)>P(~x21G<=GXSPOwS%'
    b'Zf=+6<pPo?^LKoBYaN=foz2PeICR40r&mV_a$ec@2N77RiMH`NhiF570M6mvS7LqMc|c1T@|8X1rGv;&v7l^1dp-'
    b'%?(fg($IN2PEXHTD7>GF5hz=cI8)=5^4N(muend3wQRS;l=jmQ$DWbqM8)HQHIncAgdF0U&5#@riFc>}gr06LVdj'
    b'<5so^CeA0SM>N6C(jT;%4lwS-Tib+v$l_NVm*D4tcU3^Aw-A_vd^#^rppiv|E;mOyq5*AtOZP*fu&1Ml2B7;gfd3'
    b'Ad@R1aUineHBRo&KmyQ<JAv&x$c1NP2jsKqOiNLsQ`l~VY|b$~wT`M&o&d$A#3<d}W)|b?vl#ix-0XNK32obv<VM'
    b'*|hLDCLnZ@a$k5|icCI~T*z3s{VfxfrbY&>2m3&Td$kU<wL{74+_I{S24jKM(1vUU&TMNGvSHocH`wFHU+`WbeoE'
    b'SYTK48L~)Lc3x;v1WNs3`5qQddkeOupL;_)ucJr*GQl@ZlWc=n-B1zJrEiE<L(rvkY~Ck1c!g{W9b?;Y)>&{7bja'
    b'4!{6qsWjFaa((lm$<r(M>j{V}}EXKaGYg*6ue&#>jADleATc?TbxL_@@P7|8;r#1g)c7SB{Cd0ky-F@;@{{7IeU-'
    b'3WB_q~MPtPa!bcfRi(5}%I$TR-xF-S`iFWPB;YVY1_7|GPH-74L<j6mNU7*AKei!@vA}ibbkFYc1ciJf!FUi`h&Z'
    b'_ZHl@_mb`@w%w~d$|-}gx5KitNe>@_*k!cmyj^fRZuNA38Mgxd@I-7Wd>+=!_E=+OaKAUHVHWm9%%T-L-21DO5%6'
    b'1)VR?(S9k&<wEP;C=?qQwC#sg(gwHEg**bRJWcC#sMzt*rtmM8Y%-gVxD&G!GyEXK@Y%q+%NV=>+X$4?_M0Fwjl1'
    b'+@pQ4U`Y9z)34rs6Yp$2b(Cv(pAvlQdUjr`7(e_m4RZK$ucbbFG6DAQob68Q7WYc97wG~Rpa_uNX$i0cper;`x>7'
    b'x&UE2CRy48{Fs4vw*h;O7vaUYDVN_1wRJA94Q3)ntW~>Z?stM~lC`yOD;jbDO7I@GuxD#J1zbRO$T^*=OeG44MJz'
    b'o6%`Sf#UF=iIyGg%BmYT6EYXQTavp3flikQR|nmhP2Fsv%!(1?6|g$q|vyQB9E!)lIAnGvn@TlMd&)>}_fg72S7;'
    b'qMj~`F|376wz%$Wq@0Ot!1_Zr_&pk8cYtuSF;m#r)wUU@IuqzkZ-xyaFqyY^JjXr|J>q*k5c94xV$EX8=SbE9$c$'
    b'xecd>0gWCPYW$pl4@meASQjW)R-9_o7*S9&H4(?;ZIuK8-s3=ln`al5i716`R}j7Pv?v{fGiJ?GIDNO~{nxhCa2Q'
    b'Jw{&d<kUUA>!9r(ka*;kTap>#TD{vEsz3iNlyqPIkYisE~n?LPnN}4Uk!9RUu_1PoLVbvXDR<8g`Zwg4#eV?6U#d'
    b'8;q#6H_XQ2vjalnp7sUF&&ft5n&Nuij{Jp^X0re+q{0%=PAhQ-WJHlQkc4LiWEwpVrm6LtpZ#(QcF}ZnqI74oIoI'
    b'+2gS{5U+VSmZsC-c=GvKZg(_Bwho=VHvc7;`ShoQpBD7&D9U7+H*8k>jV)7+zTOFmz4H=()cS!vLUmGEhONSuJH)'
    b'@v323A=*@B#fyU1Vd$$mtO@~@4!;DAF<r}7<1s=%P-R%SCJX}~m+UJM6n^Mb==pxBy^s<nJl$~Vd!hCnD~d2Iy`u'
    b'7bPx>zWeI5hn6M9XhG}FF<{rR#i>VW%ARe3Bd!a(~$pkSWR3#YK&I#i;lwF^0`O8sr{7;*9(|7H$j<}f~w!+3qM='
    b'@JM$?}4RNoURf3Bi^AW#wo>v*k_BFCNj4S_}M1F=7g79hvOsmPpIBukN9M-5#QW^&ji(;KjC_kb4+#fVj&SNB2L?'
    b'mh~Gx&=q+pSftPY%)C1LybT-180xOvn^~?ZXjU42<<#B2WpNfa4VCE77zXLaM>V=UF*e~@Vi3qD<|H)pOfnrRja1'
    b'6?`=Z3I9&cLn=VpGJ0?GmzwevE|qfbUw1c=e9Y9LCq@Fidnf<%5AuklyrX=z}1vV8#PI?ZiH(x{1+Dbqc`G39xpw'
    b'mN>qSVNcKj$h(8i5I%<&8lVqPITJ%{VHcZIoKR+xZAlJhm0idm8LFcivI}KMWCL&!{FX@xZykjlH+`H`gq`50Hq='
    b')G{s@?A;#~6{dt&g5Lk<}bznHH!r%B$)k?Ke~*ctV#nYa-<>;}@0I0ep&4BpEj6DO%3j!h=6@nXLFIERt&2VUY~-'
    b'FF`{7~osz?>_&IL+2lS(3G)(HF5AkQ%1n6x8c9rC)wBagyVG&a$dfv(mmn8KMfyOLytA3*YEK0d!FLq+J1A7{*a;'
    b'Z@Aqifb}2HtM{4`xckic{Qe1z`WZ&eg{uTTId$@O=PPhk(n0#5XrJ6nbO?`&8w>+W#CU@|SN7&=U*TSBFxkt#XT|'
    b'&NCQ>wM13<9w^$0=}nO5CowKo@TC)g%x2p8S_Wkgxe?e?`1e%Kx;re9!&B@BOc43F3}_f3}Gmvjq2t$zGPHIHk-c'
    b'y6>zxW$s~p2CRvMKfF$TucC~eK~PO7;t9kb4?d4L@+;MF<-_5De<!YjvIbX~G9zqcW$@kmj`$Ii*e)h+JzaLx$Hq'
    b'k1hT@ZU&8O|#PEQ=8*xo2hgEEL_{$l1YX8z)9@fY#uRFV`vG_NYkqJk<0%4rU0-arS4y(oe8Ltv{~G9Z89xKBnRi'
    b'h?=M*P5}Ae-ZW~{(5yJJcLwBshAU@C_N|Yx{#g{O(3v4MBAP$0v^<id!nkVQpwtbb&HZ~PkFWf``iW7MFWMAWe}D'
    b'y#{zb!vCGg2?kXt?tiR@}RKn+V7}P>aP1;n|!uPS`Z=#OmyZHO>7vCl8!{Yg`FJ~rWW->mL$<UUbXr}gTN6N3xbU'
    b'tiO77;W(1qGTz#D}N_NGy*wEh7F)yjlPq?5Q&S94GhG-2svQ_G&2qdPO<cjz3{0185fOM(o9~r<$89$->Z+^kj_)'
    b'59l077|2V~(_-81M?0a=PC&NA0Nrf5MugX6t*Ar7t_6ZsS&GOqrOtyE$jnjnKIX$h<Us0ig5POQT@qL(5Vf!N+9F'
    b'z~Ctikf+{Z1Da^3?CQv`X*ll$Hz6fMq7#@A*tV(OGDs7?ZMk1`Rb`8i9dtK{KKT~wfh9psPwZ*SR1wGXEgWn|#^o'
    b'U(HAVLehUl1c9Iol^_FkoM_z_{8-)Hg)7#QODs0br0zcJy}kdXUf8$4x7|b7=BUO#9)0Om1Lnak-=AD+hMDyZY!I'
    b'Z4WqKw07=1LCd3qCJyW2rbO&F#fnDu^gfrOa0=|6<+jTll=qWP%?YM;>b}Va8tzFqOkQz`N`Q-z33;iP|BTCrS?D'
    b'ls5;*c-r+LF1pWUeilYfENUV`eoTC9Cl-F!IyL4b?#4kbL0^-xmy^ohx4ww5P%fRWzcesuLB4fh=U>N>1H095A;Z'
    b'IxXdwAUA%!ps$yo;b~TfB`;a1RjnI`UDS0D@IV)^_E6(Psu*##uR_+845kFL4k}#*wemiapAjmC^C*1*2N5=9;TM'
    b'%ID|iN1HCmRHa9T6CGF9_hm$YwLD#ck*1<)v8e+wK(beG&crynz~G4mRq$!kzn>Xjx2P*!^!0b`}>%Y+-E%^5fx@'
    b'elT&W*qS;Vv`N_p9!qXm;;MioDXoKpr>RwFGX1eX3S4dxL3w`s;^(=ommksGB|&d*Zp9Jyv>Kbwu#fGrK}CClh|t'
    b'`Xu1e~x0Hc<7-H(D5oIHO3p*GU(^Gk>&yT2|0^(5YI~%Jr<a>kc1@*$P$vtJ-%S=#~aE~KRlQ1B!DWe!M;^qPWQ7'
    b'no0l(K1NUgPWY8uY}JWFOOHpXkV8pJ(h(LPoc&T}$8s%7PkTf83C6jZ3mxVERL!M;Xp%EA2qGe&14dxQU<-PnXxA'
    b'{uhk!67ZJDhQok0;CZxVS>i_EAQ7hv8BbMhG?l~&vL|3FdV1VGWY@1HY@waxJ576m52H*Mtbe>(-}1;&r3z)gTup'
    b'L<zr>o3canIM7}zTtGT6?YqRc1wPkeVx_Bg=zLoWNPrG6chjsNkEpNs8bcR%wPGoLZ@88e?T^BFUr@hJI>55Vyg8'
    b'-A80FJLKQqbse1tSjaPyyi`)Tv*p$19<If7*Xv7&>No#2~Bi$S@0(CD)A+l47!xB#$ib6x~ap`3x$@ALy#?eNE2p'
    b'SODT25!$vffSCk5>z{8>}aqL0`h0{8$-A8(5c&y}56D3ukWl^%g_Z9A6K8y_l(4iK(biDBdq)=C0;3?n3l`t1b$)'
    b's0&3mnG69-iah%wWt6#%D4ZS428D>Jmw{=JASpJuEKN!~X#Z966#D>RQ?6(|i&_R|{!@`f{3;u_9z%_4v)FnuwHY'
    b'AQrc$%V0nT$!P%kr0di)?-AEN#_5`6VoP091rV1cgk^+1Lr#k72y$Y6+6C3}pKMCF3COqYfsD3@`gUzjeMbbM$B1'
    b'&=*Hfp@oU%Wt??#L05IRAb9gq*rD(P&RX)|>mU1C4fVRe18Vso<Xkr8i#?~OBq@d#>6k_>i8HnL|x%qQv=3ER8^Y'
    b'2UJOOEnIoP1cu;7z=#IwDtsKaWShcwmJ22vW9)1dYce?aX4e!t2sa2J{dN`wT?&lvm^W)^_)5M_%~3kPDV3{lT({'
    b'VN0qlmXAimbYRYz*x(x3H$(OQPVqz+&#|RJ?&6BoNw*bAtc4OYsG47}{F>LjIFfG-YbT_kt&x8$9XV!SNIcGyY<n'
    b'6M}hUJN})MDxnu(GF^=C^)4Gh><b*<52X*O<&TCUcF+%wEjw#p7cy-ebm3Ov3=cF9g)EX*A?cEJa;~l_<T!Ri)3V'
    b'&13^>5usExTf^7fXGK^RK-87T^_L(oa3x=jyC`by$--}3<!cu@4;Lzg*1RmKy@e>7D!^fR=zJz!RZGuz4y)G4rVN'
    b'y*s^8}>xTi%O;_Nw1aOI41UkFDHRizfp)ij($;LwUOxQ_sv`gKri2}>-s;NqL$E)Fzvb^1B;7c+nHnf%2##pubMv'
    b'SK^h)}E*Ru8guNVwcDP)2$WoHK(2#xGrFE>R}1|HXg5(nURePP8sxhWUx)%QD*kj<uB|hr}?J9OgUj-vA#^)#JEQ'
    b'+n8|pm4%w?rP(M(bk$E^%6^WtVpfqhFIZ_Xc&LW14ft_edMV3OAz+E)oHftA>rYTSlLW;jL#P2!9nI!+Is%0S!&7'
    b'?%UNm=*tYKirks(uiEQm>Pv&Rd$*dM9W8;t}u{u+vN|V4qb-y<xL~_PfI|51n0YB{0~HvH@&z=nbyRr1+g=gtrj?'
    b'_k)EFOnr1$u+3!3NEqX%+am*ZbZCLI#wpWlg|($#A?cE^lAvC>X7Z12j8_XuQ<AU^^lV2qMiX7&$L>3<`-S>v(7M'
    b'Ix_VSRC1RqI#H;8)#2F{~=n0Uu%k`r(k)_Fx)WC!dgyT-u1)bj>7kI^&~Gv+;xH=5))?emZLi$gchT%G%T&V4@TK'
    b'A$s(F>@G?mBToE-pp0N{aV)z6JArgl1eDN&;_#M(14IDTp<fs7)s7L3+hS+WgukfmtMmfS60CnVKEM0bLOh%K~Pj'
    b'aZ<>&mf{W6LI@FT!pb_|f$(uTW#Z-Ri*MWvFp<)of)`jn|hD`oGk0BfG3I_iG%_wn#l?!yGDnEci)v(E$)fKO6?%'
    b'^Z@9>N=O9V%8y4L9b=;9KA^R=c}@{Qdd#bLKH-9^-T8l~82_;+N?=wxx>my`nhYAod{sB2H)?K&Na(F$f};X{u;<'
    b'MU1HpJr@%O7=D3&YfYJ_`BTorpjjg;s^i$vIs@}icI}Zec7ap7i%IjTf}di)DQ=@FlF9xCJUdnQXH;#H?oJkHDjN'
    b'}#Q>N``A9@MWGx?D!da5>SY1$*!eYL;Pv#zXN2%30H^Azw+IdvnMo;lL9udSl~kW*YaQ0@#(#+`e8K8krI!;-3m*'
    b'u!^#F-FP}IKkG|3ieGLg~WS0rg<jR=W@hxsQM^bo~XlviEL}g)@Yh;0!*>Wo^l?B21Xk4VSTY9^mxcPRni#BzYq&'
    b'yrw$?(@*;i#f44Ll^{9vwG|}dqM-?#GsV85Uub^Ae=44ixqUx-v!w9feHoy|aVK9{Agja@mrS_;ydx8xfC_iJQEn'
    b'>=|2j(&(aVE=d>eHLt-LmA+PCD^%9^>zOtlvDZWacqu9%JS)W*%eaF&-t4@hfutG#-O#RVX^onh70Lg<sVHFSRT='
    b'PFoaBjSH1h)OA=El`QcN_dS4dR@E>s|BE!mn6Blk@fdaE)nUbTS*RL@91wjW<<y*_kRtFs?qex}1`DIACiDfwtqL'
    b'wGR~LmA`Xlp7iV}-WXW@BLW6zF>K-64g9d#HeEh|ro(A6R5MJNL%ar@;w6d{M<ejE81f4|#B>D_Me{QZlW&6wGY&'
    b'+YdaQ>6%yQ=U+bJ|e`CdJ9s91=a3T#_8f}DdRe!$j}gDamxlm6^C<72qG~OQIRqu&MnPugwmdFR>r2!Q$%j<Q6n;'
    b'=NhI2~hapSzvmG`a)gxzudQ{NF1<J1NyF8(635ykT*NOQ_*FdlPTO2Kb#(>BYsweIcB_4U60I{u>XR0=d6GY+d;y'
    b'U#-Y$+qxVl5yG$S7|qD+8!2si;;N5$AnN{R$CP(iBg~YR<}d9Q{7K8}&$`3;?oWvS;`+%CP7RP4Xqgo$O9FSx^T2'
    b'NQ{LUri>>JTbIx^Vz{s-2ImHJLH$pjZeI-enk@sWlGKlrs<d*N{u3SH|GKN8N;ayik2=^D5K(&?;skPR?>jplsSg'
    b'd-IO8@sopYL~N<CJmzCBb4b~u|fr>v%nU2TBYmRSG8U?w(+CI!LI!Cq-w6VY^K>NiT0j58Idl=-xPpCy*po-IvZ{'
    b'WzPk-X1oK16#h>y_gw|nbDXTjhWGy8I76Ic!Z3`KLN;39Ai=fi~CIoC24#{?H`I-D(yotm8<+PREkwW;5D!#*+?y'
    b'^@nl_!uql0fq`m~H@&0nY8n01d9hk?6W++&#oJSK={icx!l_B#I??C2Ig`&p3>kwvCg@y3T(64!2i;wjA429qlP7'
    b'3FWlP)Ong6escD4;2t;|yg8^@2?Xa1VZ6NI&F(3_RWlQS)zv*RYEhFP^{qJ+m4!tMR$DCR3+>n!`%01|k?kC?Po_'
    b'vIp`4%BHS^8P$-CJ0Oicw}>R;XgyB#4awm|IoNhsQy+&j(D?<Z`w7ou&7=_<>c)A>S6GAOj%qs;(B|2U)ID&E=x~'
    b'bsAonGqtD7C~`<Nz^to90WBL?Ya)BTO=lJn#=<Um(3byTBHgKgj0f!3Px?f258nT{W3M4t0>L(wSYzd7OD+Z@uMV'
    b'<2K2j9Ako6GZli76o+^z3*pM<1y5lkQ@n7FQ`-JH5=C#APZ$9*c|0V5qq^-4wM6s3ENwm3=|y+QQxQ|Uq%eoNb^8'
    b'Xr))5Kn$!E;)16{My)0sy43w;;ZTo(zD@m6f<y+)aZ9a7b1u_#G>gmJdbTee*eM|r1h}gy@byrnbcWGz>4CO`%n)'
    b'b84=Gb38bw1p4)6z7VWlx<5vw`|99Qur=mrOH}4{e@OC*Px@`Y!6iOLEAG0RdW@dNkbrkkyEBe@f<#pL560x#Q>D'
    b'@pEQ1W>({|vKk-o<EN1tzVIMpQo`C*KJ!`AR29^%R-O!NzhO=2F;N##iHZws=!cY#&}gBHqAbEML~790e7(M(Ec8'
    b'SegiwD~6v8jc(hq&A3Xu*63uU0-H%i{9rf|&nJwMP=HLj{PD|t|Uq~@fQx-NMknS=^4n4h9PqFPs8P&9B`&ea-TA'
    b'rP_>4cCRQrB|w;C|$^u_$KDF{(W!m?DOg8%xBDe#%K5b9M)HQGHFM`0{7<}@jBv{Q$B2|_oTK!ZuAt>rfbALMq9C'
    b'@n21@*fu}lu>N6G{8TA*-TEsnKtDkO`22F9X=Q!EQm?oG|K0I)898ER-Y~mJH+tE;u!GZdU>_@`Jv_@2u5)&p{W!'
    b'mEVW<|X=5PwE@3>a5rf@*eXVr$i9goCMvXnVx^p1PR&xJ4&mwhrr#*mIhin-2zfFORAL`{eWlAGq#BPpW~@uQQ+V'
    b'7<zx^u&Fyn$IM#7%3EQg9cA@&(1@v@19S-XLlce{V+^c7Pf=~Ozh;!_GY}@(DoZ_I)3u-}uJMze%1YT8yN)u$U@t'
    b'dlIJ2#}<<XJ+ptjVrrllIV<vAu!5H<wt1q?=gIcah$^&NpOw#Q4B*ops(laBiRaQL({{3?9svd<EF;(Ub7PMngmQ'
    b'Qq6t8v3v&&P3P*cr2nGG)Hd61@+#5ec6_LWtKv2FFwv^9QOP^InNmybB4y8p)qG@%v{FIWjsbM;{$U1G$uoajpx-'
    b'O<h&}v!ZkJL8o(Xa<Gi2>Yp2Tw|EaRzT!o4{U=~H`ap$T=1&#kjm<+m>uf}5_u5MtEg{(_0VFO|4wAYBD!Y*CG10'
    b'o)L*Hkjl+_9R-AGj7@;9bAbQh%%mXvvwvS>sn(c}z70cH>y+d4hRLmm&F(qJ(i`*V+?>^i-f|Qma?HD*PsRjO-ta'
    b'-Sg?^%wx<v#%E7qrCB8_#2YjRAhK-+JWR2@5i}VTaelPD(#(?SnSZ+>jI9t~a*AE3KRL~1h*#@NhI2;Tgc#~5o-U'
    b'7(_tXO(@fu{XqX~~xNua402I9ogB+$8WP5t6;8P(lK8^nNXjo6ZAoM1g^W=RKGA{LB})ay~lQ*R8ya8(D4OVcH9c'
    b'G!+NVs)DwX@1N(p7w#5o@SMdJK!;3vK8de9u?(s0AqD|ver1(B_}-@@6R)j@ffDCk{;|3$J-vVhmNjqc|x;ifHNr'
    b'0r{1v17ROkgY1@2d&%h5SOLGC}S>}rRKAfOuhUR;8z#hsz<ryZ_kEgxk)RU9=IN}g;nmpTP5^Hy*Sw6sOYU-`A+D'
    b'&|4Cdg-XW1QwEOTBT^9J1ZtXaY%=xC>QqWl2vJbQ*q*_9-*!anl~Ca!eXvIoR`sI6?SX0SpM6&9ogmk+*l^q3_1_'
    b'N|h><Q$ziE|ESs|J=`z%GmkOz7&DJC^B6OaG4mLYlE?Uf96yc6XsSkYR?tAuLN}!dLS5*ZS7i|fvhbu(l@yM-Msc'
    b'N@vZ_PwRe>kCUzUL=%P+!X(6xLu9-~ph)j{YLMWaL6c)0X1a1xj9d6N083<|IC>w=Ohg4z%38V4%<QtP^gA$=qt!'
    b'=uS1RU_*_!5xWOS6E^ZaILVo3_b`ORPYnLfb-y06BLpMC4&wHmG%SgTi`M1RkBX9=kH(4Y{txHeEvk%<J8?Ur)VD'
    b'0A3gm?M5)aPBo5?7lL>*!5!IMmmh7)M{+QF$f$>gcA|HUf`g{N~9XlYiqq50;_jK6|pi7$OI8D9VAVS<KT=NC1Fy'
    b'zsxpC;R-88H#WZs@7|U~9BNl#M7{WBmvbU9sA|9UVo6C#o_rDbUn_eYN|C$U9xOG>y^@dzws1DC?RJyOt_>40TAv'
    b'@ody1YNYJn^_T<I$4RHCyC@<@N!c_roAD?nveG^W=$162xstw6wgv1QXnW7|6>N+$Z>WF6K>ca%VZ(>B8DaONQ|('
    b'^R^c({nvQw`W=+D!wGSM_?I3IAm1NEq(NhAw_Rp@id27`>KBWRpZ-x=x_dUwlP>d=Yzr!Kr^VrKKmwv@GDk~``}1'
    b'9@+Wk?5(LF22w5=y;tnsuG$;M3zexT+5Rk)(UdbW<}W^c8C)PdnBJr(<=>4K!$IHK8))>sxsN^76%}*exJ_0GiF9'
    b'(W;A9-V`emFM&mIu8vg_!KQTE&E5A~K5+!$a6SA<Vxh{EA6uj_p_N5LyS$JXKsaoh-E9Y^kaa)s3Q)^y*2~y+z<$'
    b'N_>13O_stpzJxQx?qA!Yi1lL>UTPb;V03L|rrPX<s$)HJTLy|5dyyS>dYUWBD04yT;YNlpM?Mv=>T&g@my+fpAKS'
    b'LUZP1T}q#Mu7M}1n^M3<@F38v`WAQ%6Gw~hpHDw$Mq_3)K6AE7YpFIQS)Q`w2-I+7*|4}7>Ibo!B0{R!Khqr7JX!'
    b'#e=UqlfYqgbT$WQTVgJZ6FMl(4^C*su7jQgiMqjlJwj6h_Vtd*hpsBMNdLR8n%Gvn++x#$^?D!tAJ>WM&eD~^KtW'
    b'FQ(m8Jh11`O-7_tVNU^WjC591N3yu+D_+Foq?mzBy|u)gb8$&caS$X<2|Bw%B5eA+32n&J)Gl|qQ|Ys6UvpRyc+7'
    b'wu?6~?`(``_MgzJbsCz6B1<*2dWVJb&c5#W*9m#IY+N~mFk%{d!P8TAlPL;#1v*TvSlGAyzztm{zyJBJAgsz|NjM'
    b'lZpx^`x@y-vL?Mw&4~vtbOaA?1BZ>O>5`r}F3?HUaF^l7C#tj99^Taf??*Wh2&jpzZJ2^nSWK#mW5uWXJLd{xO;6'
    b';|d!=o{52tZm3S{nh*FrZn+({H>&H0%%_<}I42;$BYfqg1C-P8NBJ2xVY_8A&o-IajG4`t*^HUZnAwcS$Y%VC96z'
    b'yR2GDv@N&xh*2sFKv+-oH41)#eOJWm(3^Au;E3Tx%+K$JcY>QWa?Qx)MCsWX|b<?Hbn9wenS*22@WRLbd~fuI_n7'
    b'eS#zS2EEsY{Y8j3g(qf!JAq$pZl&XdHE3@16EiUyeNXu3shMM&cce$tyBRVlA{)^UIlr;dx@q9N_?VS2(RMdsM`M'
    b'~X0*olo5gp@^M_wElQA<HpUGr&K;GELkpUIxJR-z&=n+9myFvtnh&yW+ItFScl#M6^=hi9egh#VIvScf;Mu<M|E_'
    b'rk(5c%}BeRsW2v(n^b5{rnLm>)#QV$;W1qkJ%kqzxgg7Kjrl)G3oVZIVrI+Rce3bml`&8SEFTEWvtT?MSjdUJZ3P'
    b'Ocpd9@(N^2QRSEql*^H~S-OWjGELpnAWbzrr*8Mkw4I*hwaO{Wp1LBkyoC;=h$g8MKznzanT$s;rFDhlOch*f8K+'
    b'xmfiCi7d9owWHFP^)t*?mid$K{uj?N9Trm3K76;oFlTB8={u-XC{P{-J8%%5(@44Frr%2yfXN9YHe*j|a9%UgGeD'
    b'Q~6ium)zD^8#DK+QIJd4~XhYQ;jp4X9Bck6Wh`pl4-5mDW3wU>Q2S0h01~Arv1Xopc6N<THt%@5w?7Sm7eUdAL9t'
    b'JX`RYi>TY7slpmE(Q<U#1Z|#zOyko{cw%w1*Eq`Dr9@c*Mp>rnu3;o^a-*M>ugCCkYg<@SC{Ls{i^3~h$-))p^?0'
    b'Uj6y9Ze>-&E<I5aFMOl&hhKPSERjNclZu@o;^=xle!S4Epc)Y1nruGP+M{`{H-+sh3h*f6Qdx<g5M_d;)v8f1Xaz'
    b'cM-#X*<`D6Kf&KyX_D=2VrxfYc#kxHi_!e2sT=F)WZu$!hh$bgbgmSe2d0p^EYrmCWKUInBoFwX{Fg$IzxijMMGR'
    b'8P|FpGy&jP{s{cql%;IrC$dYUj!ovf(S(y)ZD*$e7uMID-O&l#y&5^Ex%|FEIE(b8NW$}3zg7<H!39{k=lZ>ekXm'
    b'gU2N?sqaL)<P^ssxUR<Zm?5VUb>%6_r)$wXlgk8*EG`$+fa<suKBb*?pfJL^SR*X+B-p=YiA~7W-?|b<0~;4zk!a'
    b'QMrAn1MB$o%Y3^y9xeR>5&dL={8I~0%;LgL!D?$hRsfE;`Qcz$e8xeY}_!3mc!^M0xE`tYBFzpwz_DkstUx%F73y'
    b'obU?(@*+O@XCwN><vHT>F9V5%nV^b4|mV-{&%_vi9ph2|ui`#=7Q(uZpm$tCELdjSq_o*Axc4szeYL$`e9p#wzAX'
    b'T#u~32`(eGi{10-=gefxOvYz287E8qCzGnDIVJhZ_I5DZjzC|l#q?|^PZkvM=qz3KF-3{Vf@jpPu<a!E$jg%LC66'
    b'4ZnE^lpXF`Ebm&ri%)*`Y?I?AQMx@<=~Z0VU-X9$5!Ye@*q4p}?(bJWwUk_1R;MSVSw3`kg*0c$ltt}E)7dc5KFj'
    b'rs-HXxEvD=EZELXJDj%HqBc^=+N!8u%o+8^HOMD$v|^t5HSwKD$$G-M3bXo@rs_U%~d9kA}1p`oM|QvbdBa_0A1&'
    b'8oH!1oe45Zky1&vqfjC{l&W;zF#{ql15PJn1WSM{;SZ!fvIHw3YK#1+>_RLVk@Z~Md2b$)V2%so#1oh?FoZj{Efq'
    b'uZY#Dd2OAt>O}D2HF_glT)Kc<ZtOYb0o$$zCXz=}uA4AIM)2!pf*`=!%dnZM&x4ypZR8OB0c^_SBON+F^ak2bx86'
    b'fNjA>1?&p;2w5^i&#uoOXEF{<&pk8doQydqW6sH#nT(mqc%)3m2juu^M21oY^xhMk=CN|gE7**#OIAT~wcw&;N&('
    b'n6jjo{DLV8{q=%8Uj6q+?tp1_|^WYD#IH68=z>S|rEuomzQj+I5DDnDq-l6%ZA8yzS=<gUU#Yo==7=ghBE&1#2t8'
    b'UM&!)<T!MhA*gf<!aA`K6X`T=u6Fg6^2Do2P~l8tIYH8p>l;{m9PB<hb?hM-vW=ZTYR@z|08++?)S`P%v{E2cFbU'
    b'Qn!~YRR5xOV4dQ&lPn2uDW@bEfMjRe6^{|%HOa`%4ln+mzWh3y_csE*M&xU3#w9A2dRzBVO62mF?-L@O7%MNk$R?'
    b'>_*$WBkSBQ4^zWbx2}B&ApqazN}x85y=UGLPuVFwNd1-r|nxM06ezK3gL$+;d<zdLnj3ya$=|XY5ZCzhnj@;}n=}'
    b'wY|mIuci68BGZ$uL^K=k9`d?BBSw_Kz_+Zu?`AIJ5%m9z=*co-da4^~H?Yyu33g1gIB*`6#bbNO`UX5sGd6&?t1e'
    b'#I&LsE@cAimR%CTx8Phb()e7jfn$!29>eUhV~%o89om9<zq;3Xqywh7^(JNQOOf#%vKPUI2k+ydAsQxku&GBjfZ='
    b'aBc)%;abb`@`CbJ<T}g#J5tWhaC?CJ>dtQ!+SmT^X>8hHXGeB;ItliueD-1z_)cc260R@n_AnHo=k659BnW5<5?L'
    b'mcDOISINa~&xvcYC)_E@LJePImGiE;HQSuqT#gCuHXz)hh^c%)}q5Ps?s$xYEHcb#};Z-v5@TRKDvf@Pv)e)lRI>'
    b'0IfP2qW>QeT46cy~2lZ=MNEwJB=Pr=B6$S>d#HTFFL<z;C=#5Ou*|+0OGNcIQLT0qjL78CGHO5l%zlv;(e6*NCzV'
    b'3dPC>>n?*z)|C*<D}BzCUj?q>c+>f%W72meD=LpSI?&$)rxAa@cuqfNHe+TpK9kJ=GO#DAASZM{(+zQKAnd-y-$2'
    b'KE>HyKlK<Gdi(u|ai0dyW!Kn#bIi8@3wSm$<eF~b7;y1QZf^V7}DxTk88-j1g>8}pMDYZXt^7Vd7D*qo@o1FO#C='
    b's>K_4Je2vI$ksCPbl^(PP&^JDQYC<qq|w4u{@zkk86Q7zQ8sSSyGn_979m;$)2WDGU^jaOb1o<$0VE8R>lcUaezK'
    b'dPmS*`*+@^K*U*(E5c%CWvl(BX&4{D@NRvNv>eP_zU{mfIr(2zgErZSw(>3NvceSupJ5Cu<G|5Khr1!}k(EN@va;'
    b'_$#jtyjs>oGe&;cgkE<J3(g*~8CK_7P<q?R7@=HW3io)KAyJZYbLcYnsw_ht^Wx;V9FvFJ@_7Q~1n*YF3;u<MEP-'
    b'HKRH#yCOdZIkaoo<q_{~&NLO*(4?7>I&i?c$Ky3$Ev}|rw)6x$PWmp6GDR}6(E)PF{;2=wi-cX5Gm|kh88eeHGZ{'
    b'0JF*6yDlgW4w96xcGi74vAm9kb)5+3?4RK8ckI#eNW_R<Mb1nwXq9@M<%5}29`5vV|G!1^yjW8hN08i(QILRrCF='
    b'vSIar6kpwU?Er)@B*gcHIgeSb>#^k?gB4MEQzN)*eK%-`+W{0(6ZpVs#L99<@2x#U8PE<nUFLh#yKAjgvcYmuIhq'
    b'?tSXC=Gf@QCM9A`6;4ogS&2#*l8H}01_{`dpfvS+RWY<w;xE<{SlMz`UCLm(O`qafgUQzddsv)7idK0RUHkx|h-R'
    b'Sr<-!P|X8|hk7{mIj1Ft%!%)tK)217ccF&yQ`pJLeJBf@VBYq?j0P1a&po;C-hJ_2;CCBqMdTKqMF;YFsTLvm@0V'
    b'AiCW3Kv>w<9m~ceqCp3QyFrAw>4B-Br-mw(JDcWb=mAi72iXC=B~;13#knk7D}WA$jA!kMrZ=dW!FU8+GFsU3!_*'
    b'8$6M`O?44~!YNVQ3b_}7;#Ih|~4sm~=RWNjYM#h9mu6MVqMtd>J2@}By;0$pF8aKBGRsK-Q3nv|+bX#J_mem|PAI'
    b'^{_><^xsU_a{3{_S2bx`sW%3T^y)>1U4+NhT0Ch(=^$K_LFY9c$G<-)0z*I)3j$(zCGpBkBb}SzGq3tDQ|`<`+?4'
    b'Yw$?aKCy6mM?VX<3k8uy*++85Yi~V@N&*a6P%^fo44jFTYjJZR`%wEjw#p7cy-ebm399p6RU3gGRO<f>-$pc-g#w'
    b')zi^9s>;x@47v!LZT`w2%MG8hR+1UpKC3>Mt_11XuFaxQieVO`{4QD^mDy2f9|iE+JRgNEoWh1+Ecc7*wV2SD|dm'
    b'kY>5yC`^S-Sbd~7Mng$1stQ!?%Zb5|MIb!52f>P<@MOg*-3U)`?JHT=g}~_-jcaONmwv#$i9Vl`dOn|i&iuv9Uwk'
    b'Hi(P!<Rn}q7pH^fs&J1&8h5SxhIkVnfCb)Jk@+e_Z!oD$&ngu3D#d7RMv0K(W*f4=E)uE5WR+jQ}Cdt(4k0=xFqy'
    b'CMdLwdwT4>V(J*7>L&EI8tWH^t5ZLJKm1KTb-q+QeuHMrhXZB%+jRC$WiV8HIE3d-gjm+)N6$5b8b1+?x#E8=*@s'
    b'w95KAR(vz=jJPnllPPiH}z&;Lb9&N8w&q7a^p(8!y*P7)1H1ijafWH7{fF9hYUJS%jj1G1S`B1IGu%*l!W}_4JRl'
    b'zwy4=CeC;5?EJcx?$?n7UX3zu{b4=vxBadb$}HSLkzR+YFc|AE;js)rG{-sm;W81YXkFkYO#>)LVw8qqa6$!%mi`'
    b'd_{F4YxqH6G5Dbz_DN5TsZP$cyUxNd()=YmZrVJdPP~xiK)5TLvN{YsT~4<Wwm8Cf3ivX}pZW_B4qgKXQx6=fcj+'
    b'OM?H^@eJlM`WeRb}QG55xpdt=NT#>`<nN)F=#a{M$F!}C2~X`kvv$}sSFC`9Pjg>IZ6n<!=AGf{e81ud;S4WogAd'
    b'%Waj>6hB^FT!HbwS2vKCBpZls)Y)e^1ZV0YL7eaX|AO26@dr@RtE;_oT`G*Q)K{W7jVZ4!O38LpU0?6t+@zlQ3Qq'
    b'W^O`#-MME_@N(B{bxPoD7F3UiNfzL}PJuO8Y_(C{X>^IRHBUzipbNVr}7&D9Uxl>p3bit-<fz|eAQks`>H|8yM%$'
    b'p{Dwo^8S$WK5LJRb;EAVMK@ASl8)3QN-ohlQf-0qP17M~BnXWihDp<^fUL7SY(9%xD^FY7lWR<kW#vP#w+@^2@Gf'
    b'Tm!vkiaL5?ZLr3DN4+}pl|9q!7n1-ZMR!=cO=r`EoFYw{&Ph?@u%P+_to40s2tiHxyoey%o*1U9Ne%-ctvub|5EW'
    b'jgoZp1Hu~v|Yp}7q6tdhsj;Zqz=mKcnw3oB4T3R#Ja=FU)O)&Y8Pvu#CnLsN#08IM%caGfTCj$52hevVf(-55Rq`'
    b'UGUav!~k?<3ub2)rgqnDB=}8(WNKIbluA?hOTEL%_=!`@ievgcqMjq>W&*7&bI9?kd313CCXRNBRkCi%HXH6geDd'
    b'*sD?*nN!1y#=QNQO`{$Ht2J8p>IbqEWp*MUl(>ZnXTtQ~ZsWXrbb+3V)K`$V~k9YXozu5D+j%2PQnd?aAI+B^im|'
    b'2X+$zpr}j-N(i2z(|hE*oAnfs$UObQQ9)3YxHCWzCz~cSTXNf<beeI&?zAio$}Ix&*WizXXXvm-6*E4ByqhuCW*2'
    b'HMLWo!$G{JE|@O;I;=t*r*T!u>awVGSrkgCAglr{xK|X+ePrfpU8q`=RV8@CO9ln;geR)T1;X>2!d1E{B`!d5MMF'
    b'^n>ZRHgfeWM%UZ9I_g2RaapM`xs{hV2hnZ@}0T#POC>Sy@-W=87WNjai~iq}Bq29eQ`q8$wsCGup`J>+H}LZTTPV'
    b'ncmD<urjc=?AKf$P&YzE{j3WuBI*(qiKmr*mBd-d<l1>-kVcSdwc3Aw>hKv6Uk=CqeD+9IvY2XuZ!P=UKb3A>WYY'
    b'trg2iALCT-+&BP{|DTl)Xp(7%_=EH<&xuxgN*bf~q8}}E=l?JNC_iP7wTrBk@obrhcGtu1J^O59YuxSeMifR@N_3'
    b'os|9~Oqsi3LnEMbATF_cuH2Z~1D<&FJIRuCp}hGXjDiX#y+FyTSPpI(f3SB%8qw`FX0FiJZ#D{!Gtr^W=WW+dE}P'
    b'@<SV{qoNudtQXcbA-TXuMt8y{yA$P<S;|=v@JZs(W(hHW_q`drs~NEVi4%|~&ss<QcA*2=l_si^t=R!63y3UE4!v'
    b'z1O_shvU$7m}9{GH1k*}5~n;idWPRTxDZ<onDr)18>m~%1aT#T8;m|2WR$zps!j-S{L1KP=|8vl7tYp+pU2EJgNi'
    b'=beE9|V4=IrO%W1@m}V`c9UG@2gsdSOo5W5gLQ8<?HpsD12Qu5M1DjunEIbc%E>&c3}}HRr8`L3NL6N_@*v>;a81'
    b'N%7s`yMa3ZD$8s^0<h3e<fH7ksl_$BNo}o<;@-URbtKqAZ3hJPuS+123KCdbsHf7)!QhgIV#_n!ypHDw$9%JS)K9'
    b'k4jruy@iI!+>jYwv+2EIs{|HZ^qYsqg>0CorR>CoJQd#|a{qsrLME%4m+{K>Z&c@~&|X{nPD<vDec)+GsB_L7f4o'
    b'xg_J%w<76OCJ;YPvmy~wuksVtOIez8KwUc9?G<t6m?af-aUl%N&`g%+EV*y<_Hd>Q7|Mz<Np_)mt`lFBP%Mb!t+v'
    b';!rH+HpX|bj}cb)^E*$DAxLKz;2Srdv|sivQ>z};o$F&+Vr5z(v*>hju2+d{7N<Ucv#7>AaQZBp24`+y6~)X~!6d'
    b')=60ZQ_J@F&s}&Uxz(2BQSnzPx;f$#-Q0D<kxfzIhm<5F3Es0F=*{!C&QNPrZ>~<AL^U1y_s>!NP>UfUo0?`oj8w'
    b'$H1K6{bm}1o4Y@<Mcff1ZhbBK8;4zcXY*j;<F<ATi6CEcb><1r5U3Y;9HO*ShS9wP|0iO<=BR$V9=Hopv_WN$RnR'
    b'$$v$C!DHna7xUjG4!HoIJ({<oIbkMp1@AUDiz)h%jWVB4VJBg~WfpX0EBV2g}gT)kWd^UgN4daHYbVWmO0%z6g&&'
    b'*YeePjHXZ`U`jMz!G)8&4h42nH+4g_4p+6`sDk-YC|6fa;YlU1E@dGCs0AxOl8;gG#t9vSz6Z<qToE{5JDfW&oRC'
    b'!$NU6Bz3mwWvh!EOURIY(xD(RJ_Eb4E8$AGh6FV~CR^Y<@iHe+TpK6m0Owx#YD^n_ni4yYOF^&OBoA`!8kCVa*~<'
    b'P)k+fXv&Bx;k8FhCoJ9Bu!*Rlwzh%m3KNzI{9?jjMHg~{-V=4PANj{`#9;YF-3cVx{T2Lggv4)OHYp(<;7#a+9X?'
    b'%54$rW{3{}L$j%_*+?)}0p6Q7(Wx`}r-aF(;G9DLWPPHn@oiOR4hc1lyKwTDq<PwV3GwQ_A0_~om2REu)LDY%$x5'
    b'I?O#`}I|Gakdl)w?Tozc2}9Ur<C(bwSyMrmE&GWZ(8Q%ZAY;(Kw;blaL-|>qPgRT~X)4s?Q_JD!_F{`wLLMwzntS'
    b'Ap^FTDab+7v|_V5oU`!=#BW3lUqu-z@GbC(<a4r%Ne#_1xtUeoK|TV03hPL9TA83)oJ<g#=*R}AJbRN&`Sra`s1r'
    b'$cg$-S(`=Oz3tJ8$m9y&{`(dk6JR}J(%UaeW29^mu38+@LeW;PA$OaAeRtLg5r+3dQ0xt|%0nbDXTjhWGy8I76Ic'
    b'#Mq3KLN;3BQ==f4c86qpr|WosDmPVp~toIJzodX4;#-9LO|}qa{&uP<$Ka+qQZB|Qhkv|8SgLW>-GH9p4T)oC}@V'
    b'NS1Uhcm9Au{VYs1JlwQCpRyDO(_*k~magY0j*9a9hQWaBY&flB4$~bE{_W~l3Bwnz<RgEk~*yunN9*&`k#^V(yf{'
    b'Dhy))lKIca>&g5&Dmx*Z80RAImhSng'
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
