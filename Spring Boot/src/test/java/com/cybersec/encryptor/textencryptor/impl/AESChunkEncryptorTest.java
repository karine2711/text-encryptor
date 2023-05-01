package com.cybersec.encryptor.textencryptor.impl;

import com.cybersec.encryptor.textencryptor.KeyGenerator;
import com.cybersec.encryptor.textencryptor.impl.aes.AES;
import java.util.Arrays;
import org.junit.jupiter.api.Test;


class AESChunkEncryptorTest {

    @Test
    void encrypt() {
        AES aes = new AES(KeyGenerator.generate());
        byte[] cyperText = aes.encrypt("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed auctor sapien nec mauris pretium, sed gravida est dignissim. Integer feugiat volutpat mauris, in bibendum orci varius sed. Vestibulum sodales lectus elit, sit amet venenatis justo tincidunt in. Nunc finibus nibh vitae ipsum tristique, id viverra velit aliquam. Vivamus et ante metus. Maecenas ac consectetur lorem. Sed vel orci justo. Duis tristique dolor eu dui laoreet venenatis. Sed pellentesque, libero vel porttitor iaculis, nibh nibh tincidunt velit, sed consequat sapien sapien ac enim. Suspendisse consectetur, odio in bibendum viverra, nulla libero tristique purus, ac fermentum velit odio eu mi. Nulla facilisi. Phasellus commodo, dolor eget tempor congue, ipsum metus imperdiet nibh, a luctus enim nulla id libero.");
        System.out.println(Arrays.toString(cyperText));
        System.out.println(aes.decrypt(cyperText));
    }


}