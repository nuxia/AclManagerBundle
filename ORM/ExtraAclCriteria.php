<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\ORM\Query;

class ExtraAclCriteria
{
    /** @var Query */
    protected $query;

    /** @var AclWalker */
    protected $walker;

    /** @var string  */
    protected $expr;

    /** @var int */
    protected $sqlParamIndex;

    /** @var  Query\ParserResult */
    protected $parserResult;

    /**
     * @param Query     $query
     * @param AclWalker $walker
     */
    public function __construct(Query $query, AclWalker $walker)
    {
        $this->query = $query;
        $this->walker = $walker;
        $this->parameters = array();

        $class = new \ReflectionClass('Doctrine\\ORM\\Query\\SqlWalker');
        $parserResultProperty = $class->getProperty('parserResult');
        $parserResultProperty->setAccessible(true);

        $sqlParamIndexProperty = $class->getProperty('sqlParamIndex');
        $sqlParamIndexProperty->setAccessible(true);

        $this->parserResult = $parserResultProperty->getValue($this->walker);
        $this->sqlParamIndex = $sqlParamIndexProperty->getValue($this->walker);
    }

    /**
     * @param string $tableName
     * @param string $dqlAlias
     *
     * @return string
     */
    public function getSQLTableAlias($tableName, $dqlAlias)
    {
        return $this->walker->getSQLTableAlias($tableName, $dqlAlias);
    }

    /**
     * @param string $expr
     */
    public function setExpression($expr)
    {
        $this->expr = $expr;
    }

    /**
     * @param array $parameters
     */
    public function setParameters(Array $parameters = array())
    {
        foreach($parameters as $value){
            $key = 'acl_'.$this->sqlParamIndex;
            $this->query->setParameter($key, $value);
            $this->parserResult->addParameterMapping($key, $this->sqlParamIndex++);
        }
    }

    /**
     * @return string
     */
    public function getExpression()
    {
        return $this->expr;
    }
}