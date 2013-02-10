# README.txt

cs255-project1 milestone 1 & 2 (Winter 2013)

Project Group Members:  Hai Xiao            SUNetID: haixiao
                        Amit Chattopadhyay           amitch


Special note to run project code and facebook functional testing:

    -   Just as handout requires, user needs to create an key-DB password at login if it is the 1st time after extension
        installed. As re-visiting user, code will prompt he/she to confirm the password that was set earlier on.  Within
        the same session, the password prompting(create or confirm) will happen only once, comforming to the requirement.
        But there is an exception - the same session idle timeout, issue details and solution as:
        Issue: if an active session was left idle till timeout, it's persistent localStorage objects got disappeared (vs.
               really lost) for some reason (but refresh the same page afterward would have them recovered).The exception
               would break the simple assumption that user would not need to re-enter password in a session except at its
               beginning. But we decide not to fix this exceptional case, in favor of keeping the code logic simple/clear.
        Solution: As a temporary solution, we just prompt user with more made sense messages so they could click 'Cancel'
               instead of 'OK' (whenever user is improperly prompted to create database password AGAIN due to underlying
               localStorage bug) to bail out the database inconsistency in case of session timeout:) There are times you
               need an extra refresh on group page to have encrypted messages show up correctly, due to race conditions!

    -   Milestone 2 fixed an issue of leaving user identification and database inconsistency due to salts be regenerated
        improperly even when 'password == null',  in the circumstance that 'Cancel' was chosen at password prompt due to
        prior (bullet above) suggested work around to idle session timeout. The fix is just not to re-generate salts and
        database key materials if user bail out the password prompt loop with 'Cancel', or when password is set to null!
        The underlying issue of disappearing localStorage object from session idle timeout isn't addressed. But we still
        try to make safer code & keep functions consistent. Root cause isn't really exposed if there is not localStorage
        problem at first place, and 'Cancel' as solution to the overloaded user password creation prompt as consequence.
        (So now just remember to click 'Cancel' at password creation window if you had already created earlier, you can
        do this either from refreshing a session page that is idle timeout, or from starting a new session if its prior
        was idle timeout and closed improperly. Whatsoever you will later be directed to prompt for confirming password:)

    -   For return users, at beginning code will prompt for password confirmation. IF it does not pass verfication, code
        will keep prompt w/o bail out. We believe a more secure way of doing this, is only prompt for a number of times,
        IF still fail, then go ahead erase all the user related stuff from localStorage and sessionStorage, so user will
        start over again. This is good in practice, but we did NOT implement this due to time constraint and main focus:)

    -   User should never manually add a group key (www.facebook.com/settings) with a string value at their free choice.
        The use case for a user to add a group key through "Add Key" button is when he/she needs to roll-in an exact key
        from group peer (symmetric key),  this key should be given by peer through outbound channel (mail, phone, paper).

    -   User should use "Generate New Key" to generate a group key if he/she is the first in group to do so, then he/she
        should provide this generated group key to all peers in this group through outbound channel (mail, phone, paper).

    -   The group keys are base64 encoded strings of 384Bit random value with cryptographic entropy(GetRandomValues(12))
        128Bit of it is used as AES128 E/D key, other 2x128Bit of it is used as ECBC-MAC keys build on top AES128 cipher.
        (Due to longer key representation, increased 'CS255 Keys' table width to 100 to enable base64 key string display)

    -   All random numbers (message group keys, CTR random nonce, user password hash salt, group-keys DataBase E/D/M key
        derivation salt for pbkdf2) used in code are from GetRandomValues(), which is cryptographic secure with entropy!

    -   All salts are moved to 256Bit with stronger entropy, main salts are: user password hash salt, salt for deriving
        user's key-DB E/D key, salt for deriving user's key-DB MAC key.

    -   Use pbkdf2 to derive per user group-keys DataBase E/D key and MAC keys separately from user password;  and using
        different salts.

    -   User password is the ultimate to validate an user, so it's never saved anywhere neither local or session Storage.
        To validate a revisiting user, we have to save its password salt (random) out to persistent localStorage.

    -   In persistent localStorage, we also save encrypted group-keys DataBase and salts used for E/D/MAC key derivation
        (used by pbkdf2 together with password). We never save the DataBase E/D/MAC keys (with DB) in persistent store!!

    -   In sessionStorage, we only store the groups-keys DataBase's E/D/MAC key (recomputed aft. user authentication) vs.
        DB (decrypted) itself, even sessionStorage is believed to be not shared (so secure) w. other sessions, and short
        lived only to its closeure. As we have group-keys DB salts stored in localStorage,  so based on a valid user pwd
        input, code can always re-generate the consistent E/D/MAC keys for the user's group-keys DataBase (using pbkdf2).

    -   All objects in localStorage and sessionStorage are stored with per user UUID or name, namely its an unique ID by
        by facebook through HTTP cookie after facebook server's user login authentication. So that we can have more than
        one users to share the system (namely machine and browser) vs. session, sequentially most likely if there is any.

    -   We chose to store one group-keys DataBase per user (vs. save per group, e.g) as encrypted object in localStorage,
        we save one object of this (differently encrypted, as every user have different derived DB E/D key, and keys map)
        for each user sharing/using the system (machine and browser). No active attack avoidance mechanism is introduced!

    -   We havenot done extensive coding for extra security even have thought, e.g plaintext/DB length hiding by padding.
        Given more time, these can be done :)

    -   We choose AES encryption/decryption with 128Bit key length in CTR mode, build on top sjcl.cipher.aes premitives.
        CTR mode is chosen according to various advantages comparing to CBC (CBC mode is also applicable to the project).
        CTR advantages: parallel processing, better error term bound, no dummy padding necessary, more general (PRF) etc.

    -   For the CTR mode implementation in code, we use random nonce counter mode (96Bit nonce for much better Sem. Sec.):
        We pick a 96Bit random nonce for every message to be encrypted, for every nonce given we maintain a 32Bit counter
        per message blocks. Simplified requirement to this many-time key scheme is each message len < 2^32 block (FB msg),
        and cipher key may only need a change after every 2^48 messages (due to the 96Bit random nonce & birthday paradox)
        It is clear none of these limition is a real concern to this project, for 1) facebook message len is very limited
        (Post < 10,000 chars, Comment < 8,000 chars);  2) 2^48 messages could be more than a number any group can ever do!
        So this construct should work fine, and no cipher key (a group's messaging key) renew are required.

    -   We also build a crypto/secure hash (128Bit AES key) using sjcl.cipher.aes constructs, this hash generates 128Bit
        digest (due to relatively small 128Bit AES block size). It is used to hash(password||salt) to validate an user's
        password later on with the truely random salt saved in persistent localStorage. The password hash salt is truely
        necessary to prevent rainbow table attacks by attacker - where attacker search through huge prebuilt hash(words)
        table to find a guess of password if it's low in entropy (for example a word from dictionaries)!
        The construct of this approach (used in code) is:
            store ( aes128_hash(user's input password || salt) || salt)     ==> localStorage
        For valiodation, we just need to re-compute and compare the aes128_hash(user's input password || salt) from salt!
        The construct is believed to be secure enough given the collision resistency from underlying secure hash and salt.

    -   With this aes128_hash() in place, we could use another approach to validate user identity through password input,
        that is hash the per user E/D/MAC keys to the group-keys DataBase (keys derived by pbkdf2) along with salt, then
        save the result to the persistent localStorage together with the salt, so the construct of this approach is:
            store ( aes128_hash(user's DB E/D/MAC keys || salt) || salt) ==> localStorage
        But we choose to code up the first approach in above. 

    -   The string we chose to store (localStorage) the secure hash digest along with salt is:
            base64(digest) + '|' + base64(salt)
        We can do this, because '|' is not a base64 char. So we use it as splitter in code.

    -   For the aes128_hash(), we use Merkle-Damgard Construction with Davies-Meyer compression with a fixed IV (128Bit).
        We take that fixed IV from MD5 implementation. 128Bit Digest isn't very long but it seems enough to the facebook
        application criteria -assuming underlying sjcl.cipher.aes is an ideal cipher, then with 128Bit block/digest size,
        it takes O(2^64) evaluations of AES (E,D) to find a hash collision (the birthday paradox).

    -   For the aes128_hash(), we use Merkle-Damgard Compliant but simple length padding scheme:
        If message is exact even number of blocks, we add 128Bit padding as "1...0||(64Bit length encoding)" at the end.
        If message does not end w/. block boundry, we first add "1...0" to its last block, then add 128Bit padding as
                                                                            "0...0||(64Bit length encoding)" at the end.

    -   This design of the project is not to prevent active attack, as one user can still remove or overwrite the cipher
        text data of another user if they happen to share the machine or browser.  Instead the implementaion is designed
        to prevent passive attack as much as possible, i.e. user can't get any useful info of another even they share PC.

