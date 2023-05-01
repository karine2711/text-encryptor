package com.cybersec.encryptor.textencryptor.impl.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.cybersec.encryptor.textencryptor.KeyGenerator;
import org.junit.jupiter.api.Test;


class AES128Test {
    private static final String text =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed auctor sapien nec mauris pretium, sed gravida est dignissim. Integer feugiat volutpat mauris, in bibendum orci varius sed. Vestibulum sodales lectus elit, sit amet venenatis justo tincidunt in. Nunc finibus nibh vitae ipsum tristique, id viverra velit aliquam. Vivamus et ante metus. Maecenas ac consectetur lorem. Sed vel orci justo. Duis tristique dolor eu dui laoreet venenatis. Sed pellentesque, libero vel porttitor iaculis, nibh nibh tincidunt velit, sed consequat sapien sapien ac enim. Suspendisse consectetur, odio in bibendum viverra, nulla libero tristique purus, ac fermentum velit odio eu mi. Nulla facilisi. Phasellus commodo, dolor eget tempor congue, ipsum metus imperdiet nibh, a luctus enim nulla id libero.";

    @Test
    void testAes() {
        AES128 aes128 = new AES128(KeyGenerator.generate());
        String cyperText = aes128.encrypt(text);
        assertEquals(text, aes128.decrypt(cyperText));
    }
}