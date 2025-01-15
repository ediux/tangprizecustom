const ext = EXTENSIONS["@aspnetmaker/tangprizecustom"];

if (ext.Enabled) {
	namespaces.delete("Ganss.XSS");
	namespaces.add("Ganss.Xss");
	namespaces.add("static Ganss.Xss.HtmlSanitizer");
}
