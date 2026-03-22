const helpers = require('./helpers');

class ItemValidator {
  validate(item) {
    if (!item.name || !item.price) {
      throw new Error('Invalid item');
    }
    return true;
  }
}

function formatPrice(price) {
  return `$${price.toFixed(2)}`;
}

exports.ItemValidator = ItemValidator;
exports.formatPrice = formatPrice;
