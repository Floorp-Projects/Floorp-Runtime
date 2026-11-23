
#[cfg(test)]
mod tests {
    use super::*;
    use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};

    const INPUT: &str = "Mozilla Firefox Firefox Mozilla";
    const FTL: &str = "\
-brand = Firefox
literal = Mozilla Firefox
name = Tab: { $name }
attribute = Firefox
    .title = Mozilla: { $name }
term = { -brand }: { $name }
choice = { $kind ->
   [Mozilla] Firefox: { $name }
  *[other] Mozilla: { $name }
}
number = Firefox { $count }
";

    fn format(id: &str, attr: Option<&str>, transform: fn(&str) -> Cow<'_, str>) -> String {
        let resource = FluentResource::try_new(FTL.to_owned()).unwrap();
        let mut bundle = FluentBundle::new(vec!["en-US".parse().unwrap()]);
        bundle.set_use_isolating(false);
        bundle.set_transform(Some(transform));
        bundle.add_resource(resource).unwrap();
        let mut args = FluentArgs::new();
        args.set("name", INPUT);
        args.set("kind", "Mozilla");
        args.set("count", 42);
        let message = bundle.get_message(id).unwrap();
        let pattern = match attr {
            Some(name) => message.get_attribute(name).unwrap().value(),
            None => message.value().unwrap(),
        };
        let mut errors = vec![];
        let value = bundle.format_pattern(pattern, Some(&args), &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        value.into_owned()
    }

    #[test]
    fn brand_literals_and_terms() {
        assert_eq!(format("literal", None, transform_brand), "Ablaze Floorp");
        assert_eq!(format("term", None, transform_brand), format!("Floorp: {INPUT}"));
    }

    #[test]
    fn preserve_page_title_argument() {
        assert_eq!(format("name", None, transform_brand), format!("Tab: {INPUT}"));
    }

    #[test]
    fn preserve_attribute_argument() {
        assert_eq!(format("attribute", Some("title"), transform_brand), format!("Ablaze: {INPUT}"));
    }

    #[test]
    fn preserve_selector_and_number() {
        assert_eq!(format("choice", None, transform_brand), format!("Floorp: {INPUT}"));
        assert_eq!(format("number", None, transform_brand), "Floorp 42");
    }

    #[test]
    fn pseudo_locales_preserve_argument() {
        for transform in [transform_accented as fn(&str) -> Cow<'_, str>, transform_bidi] {
            let value = format("name", None, transform);
            assert!(value.contains(INPUT), "{value}");
            assert_ne!(value, format!("Tab: {INPUT}"));
        }
    }
}
