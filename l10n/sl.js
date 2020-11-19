OC.L10N.register(
    "user_saml",
    {
    "This user account is disabled, please contact your administrator." : "Ta uporabniški račun je onemogočen. Stopite v stik s skrbnikom sistema.",
    "Saved" : "Shranjeno",
    "Provider" : "Ponudnik",
    "Unknown error, please check the log file for more details." : "Neznana napaka; več podrobnosti je zapisanih v dnevniški datoteki.",
    "Direct log in" : "Račun ni zagotovljen",
    "SSO & SAML log in" : "Prijava SSO in SAML",
    "This page should not be visited directly." : "Ta strani naj ne bi bilo mogoče obiskati neposredno.",
    "Provider " : "Ponudnik",
    "X.509 certificate of the Service Provider" : "Potrdilo X.509 ponudnika storitev",
    "Private key of the Service Provider" : "Zasebni ključ ponudnika storitev",
    "Indicates that the nameID of the <samlp:logoutRequest> sent by this SP will be encrypted." : "Določa, da bo ID imena <samlp:logoutRequest> poslan prek tega ponudnika storitev, šifriran.",
    "Indicates whether the <samlp:AuthnRequest> messages sent by this SP will be signed. [Metadata of the SP will offer this info]" : "Določa, ali naj bodo sporočila,  <samlp:AuthnRequest>poslana prek tega spletnega ponudnika, podpisana. [Ponudnik omogoča pregled metapodatkov med podrobnostmi]",
    "Indicates whether the  <samlp:logoutRequest> messages sent by this SP will be signed." : "Določa, ali naj bodo sporočila, <samlp:logoutRequest> poslana prek tega spletnega ponudnika, podpisana.",
    "Indicates whether the  <samlp:logoutResponse> messages sent by this SP will be signed." : "Določa, ali naj bodo sporočila, <samlp:logoutResponse>poslana prek tega spletnega ponudnika, podpisana.",
    "Whether the metadata should be signed." : "Ali naj bodo metapodatki podpisani.",
    "Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and <samlp:LogoutResponse> elements received by this SP to be signed." : "Določa zahtevo, da bodo predmeti <samlp:Response>, <samlp:LogoutRequest> in <samlp:LogoutResponse>, prejeti prek ponudnika storitev, podpisani.",
    "Indicates a requirement for the <saml:Assertion> elements received by this SP to be encrypted." : "Določa zahtevo, da bodo  predmeti <saml:Assertion>, prejeti prek ponudnika storitev, šifrirani.",
    "Indicates if the SP will validate all received XML." : "Določa, ali bo ponudnik storitev overil vse prejete datoteke XML.",
    "Algorithm that the toolkit will use on signing process." : "Algoritem, ki ga uporabljajo orodja za postopek prijave.",
    "Attribute to map the UID to." : "Atribut za preslikavo UID.",
    "Only allow authentication if an account exists on some other backend. (e.g. LDAP)" : "Overitev dovoli le, če račun obstaja na nekem drugem ozadnjem programu (npr. LDAP)",
    "Attribute to map the displayname to." : "Atribut za preslikavo prikaznega imena.",
    "Attribute to map the email address to." : "Atribut za preslikavo elektronskega naslova.",
    "Attribute to map the quota to." : "Atribut za preslikavo količinske omejitve.",
    "Attribute to map the users groups to." : "Atribut za preslikavo uporabniških skupin.",
    "Attribute to map the users home to." : "Atribut za preslikavo uporabnikove osebne mape.",
    "Email address" : "Elektronski naslov",
    "Encrypted" : "Šifrirano",
    "Entity" : "Entiteta",
    "Kerberos" : "Kerberos",
    "Persistent" : "Nenehno",
    "Transient" : "Prehodno",
    "Unspecified" : "Nedoločeno",
    "Windows domain qualified name" : "Ime domene Windows",
    "X509 subject name" : "Ime predmeta X509",
    "Use SAML auth for the %s desktop clients (requires user re-authentication)" : "Uporabi overitev SAML za odjemalec %s (zahteva ponovno overitev uporabnika)",
    "Optional display name of the identity provider (default: \"SSO & SAML log in\")" : "Izbirno prikazno ime ponudnika istovetnosti (privzeto: »Prijava SSO in SAML«)",
    "Allow the use of multiple user back-ends (e.g. LDAP)" : "Dovoli uporabo več uporabniških računov (na primer LDAP)",
    "SSO & SAML authentication" : "Overitev SSO in SAML",
    "Authenticate using single sign-on" : "Overi z uporabo enojne prijave",
    "Open documentation" : "Odpri dokumentacijo",
    "Make sure to configure an administrative user that can access the instance via SSO. Logging-in with your regular %s account won't be possible anymore, unless you enabled \"%s\" or you go directly to the URL %s." : "Uporabniku s skrbniškimi dovoljenji je treba nastaviti dostop prek SSO. Prijava z običajnim računom %s bo mogoča le, če omogočite »%s« oziroma se povežete prek povezave URL %s.",
    "Make sure to configure an administrative user that can access the instance via SSO. Logging-in with your regular %s account won't be possible anymore, unless you go directly to the URL %s." : "Uporabniku s skrbniškimi dovoljenji je treba nastaviti dostop prek SSO. Prijava z običajnim računom %s bo mogoča izključno prek povezave URL %s.",
    "Please choose whether you want to authenticate using the SAML provider built-in in Nextcloud or whether you want to authenticate against an environment variable." : "Izberite, ali naj se overitev izvede z uporabo vgrajene možnosti SAML v okolju Nextcloud ali pa bo overitev potekala prek okoljskih spremenljivk.",
    "Use built-in SAML authentication" : "Uporabi vgrajeno overitev SAML",
    "Use environment variable" : "Uporabi okoljsko spremenljivko",
    "Global settings" : "Splošne nastavitve",
    "Remove identity provider" : "Odstrani ponudnika istovetnosti",
    "Add identity provider" : "Dodaj ponudnika istovetnosti",
    "General" : "Splošno",
    "Service Provider Data" : "Podatki ponudnika storitev",
    "If your Service Provider should use certificates you can optionally specify them here." : "Če naj ponudnik storitve uporabi potrdilo, ga je izbirno mogoče določiti na tem mestu.",
    "Show Service Provider settings…" : "Pokaži nastavitve ponudnika storitve ...",
    "Name ID format" : "Zapis določila ID imena",
    "Identity Provider Data" : "Podatki ponudnika istovetnosti",
    "Configure your IdP settings here." : "Prilagoditev nastavitev IdP.",
    "Identifier of the IdP entity (must be a URI)" : "Dololilo IdP (zapisano kot naslov URI)",
    "URL Target of the IdP where the SP will send the Authentication Request Message" : "Ciljni naslov URL za IdP, kamor bo ponudnik storitev poslal sporočilo o zahtevi overitve.",
    "Show optional Identity Provider settings…" : "Pokaži izbirne nastavitve IP (ponudnika istovetnosti) ...",
    "Public X.509 certificate of the IdP" : "Javno potrdilo X.509 IdP",
    "Attribute mapping" : "Preslikave atributov",
    "Show attribute mapping settings…" : "Pokaži nastavitve preslikave atributov ...",
    "Security settings" : "Varnostne nastavitve",
    "For increased security we recommend enabling the following settings if supported by your environment." : "Iz varnostnih razlogov je priporočljivo omogočiti nekatere nastavitve, če so te podprte znotraj zagnanega okolja.",
    "Show security settings…" : "Pokaži varnostne nastavitve ...",
    "Signatures and encryption offered" : "Ponujeno podpisovanje in šifriranje",
    "Signatures and encryption required" : "Zahtevano podpisovanje in šifriranje",
    "Download metadata XML" : "Prejmi datoteko metapodatkov XML",
    "Reset settings" : "Ponastavi nastavitve",
    "Metadata invalid" : "Neveljavni metapodatki",
    "Metadata valid" : "Veljavni metapodatki",
    "Error" : "Napaka",
    "Login options:" : "Možnosti prijave:",
    "Choose a authentication provider" : "Izbor ponudnika overitve"
},
"nplurals=4; plural=(n%100==1 ? 0 : n%100==2 ? 1 : n%100==3 || n%100==4 ? 2 : 3);");
