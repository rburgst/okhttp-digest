package com.burgstaller.okhttp.digest.fromhttpclient;

/**
 * Helper class for formatting headers.
 */
public class BasicHeaderValueFormatter {
    public static final BasicHeaderValueFormatter DEFAULT  = new BasicHeaderValueFormatter();

    public StringBuilder formatNameValuePair(StringBuilder charBuffer, NameValuePair nvp, boolean quote) {

        charBuffer.append(nvp.getName());
        String value = nvp.getValue();
        if(value != null) {
            charBuffer.append('=');
            this.doFormatValue(charBuffer, value, quote);
        }

        return charBuffer;
    }

    protected void doFormatValue(StringBuilder buffer, String value, boolean quote) {
        boolean quoteFlag = quote;
        int i;
        if(!quote) {
            for(i = 0; i < value.length() && !quoteFlag; ++i) {
                quoteFlag = this.isSeparator(value.charAt(i));
            }
        }

        if(quoteFlag) {
            buffer.append('\"');
        }

        for(i = 0; i < value.length(); ++i) {
            char ch = value.charAt(i);
            if(this.isUnsafe(ch)) {
                buffer.append('\\');
            }

            buffer.append(ch);
        }

        if(quoteFlag) {
            buffer.append('\"');
        }

    }


    protected boolean isSeparator(char ch) {
        return " ;,:@()<>\\\"/[]?={}\t".indexOf(ch) >= 0;
    }

    protected boolean isUnsafe(char ch) {
        return "\"\\".indexOf(ch) >= 0;
    }
}
