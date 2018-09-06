var exports = module.exports = {};


exports.displayConsent = function(scope, res) {
    res.write('<form action="/rcs/consent" method="post" name="scopeForm">');
    for  (row = 0; row < scope.length; row++){
        res.write('<div>');
    res.write('<input type="checkbox" id="'+scope[row]+'" value="'+scope[row]+'" unchecked name="'+scope[row]+'" />');
    res.write('<label for="'+scope[row]+'">'+scope[row]+'</label>');
    res.write('</div>');
    res.write('<input type="submit" value="Sign" name="submit"></input>')
    res.end('</form>');
  }
}
