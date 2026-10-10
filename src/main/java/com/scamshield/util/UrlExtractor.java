package com.scamshield.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlExtractor {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "\\b((?:https?://|www[0-9]?\\.)[a-zA-Z0-9+&@#/%?=~_|!:,.;\\-]*[a-zA-Z0-9+&@#/%=~_|])",
            Pattern.CASE_INSENSITIVE
    );

    public static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null || text.isBlank()) {
            return urls;
        }

        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String match = matcher.group(1);
            if (!urls.contains(match)) {
                urls.add(match);
            }
        }
        return urls;
    }
}
