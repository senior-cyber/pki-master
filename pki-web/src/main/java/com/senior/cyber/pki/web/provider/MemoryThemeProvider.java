package com.senior.cyber.pki.web.provider;

import com.senior.cyber.webui.frmk.model.BrandColor;
import com.senior.cyber.webui.frmk.model.Theme;
import com.senior.cyber.webui.frmk.provider.IThemeProvider;

public class MemoryThemeProvider implements IThemeProvider {

    @Override
    public Theme fetchTheme() {
        Theme theme = new Theme();
        theme.setBrandColor(BrandColor.Light);
        return theme;
    }

}
