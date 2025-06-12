module.exports = {
  extends: '@mate-academy/eslint-config',
  env: {
    jest: true
  },
  rules: {
    'no-proto': 0,
    "no-shadow": ["error", { "allow": ["err", "req", "res"] }],
    "no-console": "off"
  },
  plugins: ['jest']
};
