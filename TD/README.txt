DE SOUSA CARDOSO Raimundo Vitor

Q1) Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?
    
    R = L'algorithme de chiffrement utilisé dans la fonction xorcrypt est 
    appelé "XOR cipher" ou "chiffrement par ou-exclusif". Cet algorithme 
    n'est pas considéré comme robuste car il est vulnérable à de nombreuses 
    attaques, notamment celles basées sur des analyses de fréquence des 
    caractères ou des motifs dans le texte chiffré. 
    
    
Q2) Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

    R = Parce que fait ça ne garantit pas l'authenticité des données. Un attaquant 
    pourrait simplement remplacer le fichier chiffré par un autre fichier 
    chiffré avec une autre clef et un autre sel, mais ayant le même hachage.
    
    Par contre, Utiliser un HMAC est une meilleure solution, car cela 
    permet d'ajouter une clé secrète pour l'authentification des données. 

Q3) Pourquoi il est préférable de vérifier qu'un fichier token.bin
    n'est pas déjà présent ?
    
    R = Il est préférable de vérifier si le fichier token.bin existe 
    déjà avant de le créer car cela permet d'éviter de l'écraser 
    accidentellement s'il a déjà été créé précédemment. Si le fichier 
    est déjà présent, cela peut indiquer que les éléments cryptographiques 
    ont déjà été créés et sauvegardés, donc il n'est pas nécessaire de les 
    recréer et de les envoyer à nouveau au CNC. 
    
Q4) Comment vérifier que la clef la bonne ?

    R = Dans le cas d'un chiffrement symétrique avec une clé secrète, 
    il est généralement suffisant de tenter de déchiffrer un petit 
    fragment du fichier chiffré avec la clé fournie. Si le déchiffrement 
    réussit, il est raisonnable de supposer que la clé est correcte. 
    En revanche, si le déchiffrement échoue, il est très probable que la clé 
    soit incorrecte.

