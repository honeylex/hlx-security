<?php

namespace Foh\SystemAccount\User\Projection\Standard\Embed;

use Foh\SystemAccount\User\Projection\Standard\Embed\Base\DefaultTokenType as BaseDefaultTokenType;

/**
 *
 * This class reflects the declared structure of the 'DefaultToken'
 * entity. It contains the metadata necessary to initiate and manage the
 * lifecycle of 'DefaultTokenEntity' instances. Most importantly
 * it holds a collection of attributes (and default attributes) that each of the
 * entities of this type supports.
 *
 * For more information and hooks have a look at the base classes.
 */
class DefaultTokenType extends BaseDefaultTokenType
{
    //public function getDefaultAttributes()
    //{
    //    $attributes = parent::getDefaultAttributes();
    //    $attributes['language'] = new Your\Custom\LanguageAttribute('language', array('default' => 'en_UK'));
    //    $attributes['foobar'] = new Your\Custom\FooBarAttribute('foobar');
    //    return $attributes;
    //}
    //
    //protected function getEntityImplementor()
    //{
    //    return '\\Your\\Custom\\Entity';
    //}
}
