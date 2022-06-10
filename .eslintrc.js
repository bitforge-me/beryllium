module.exports = {
    "env": {
        "browser": true,
        "es2021": true,
        "jquery": true
    },
    "globals": {
        "bootbox": true
    },
    "extends": [
        "standard"
    ],
    "parserOptions": {
        "ecmaVersion": "latest"
    },
    "rules": {
        "indent": ["error", 4, { "ignoreComments": true }],
        "semi": ["error", "always"],
        "space-before-function-paren": ["error", "never"],
        "object-curly-spacing": ["error", "never", { "objectsInObjects": true }],
        "no-unused-vars": ["warn", { "vars": "local" }],
        "spaced-comment": ["off"]
    },
    "plugins": [
        "@eladavron/eslint-plugin-jinja",
        "eslint-plugin-html"
    ]
}
