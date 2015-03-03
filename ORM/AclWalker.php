<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\ORM\Query;
use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param \Doctrine\ORM\Query\AST\WhereClause $whereClause
     *
     * @return string
     */
    public function walkWhereClause($whereClause)
    {
        $sql = parent::walkWhereClause($whereClause);
        $query = $this->getQuery();

        $identities = $query->getHint(AclFilter::ACL_IDENTIFIERS);
        $mask = $query->getHint(AclFilter::ACL_MASK);
        $extraCriteria = $query->getHint(AclFilter::ACL_EXTRA_CRITERIA);

        if(empty($sql)){
            $sql .= ' WHERE ( s.identifier IN ('.implode(', ', $identities).') AND ';
            $sql .= ' e.mask >= '.$mask.') ';
        }

        if($extraCriteria instanceof \Closure){
            $criteria = new ExtraAclCriteria($query, $this);
            $extraCriteria($criteria);

            $sql .= ' '.$criteria->getExpression().' ';
        }

        return $sql;
    }

    /**
     * @param $fromClause
     *
     * @return string
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause);
        $query = $this->getQuery();
        $alias = $query->getHint(AclFilter::ACL_IDENTIFIER_ALIAS);

        $sql .= ' INNER JOIN acl_object_identities as o ON o.object_identifier = '.$this->getSQLTableAlias('client', $alias).'.id ';
        $sql .= ' INNER JOIN acl_classes c ON c.id = o.class_id ';
        $sql .= ' LEFT JOIN acl_entries e ON (e.class_id = o.class_id AND (e.object_identity_id = o.id OR e.object_identity_id IS NULL )) ';
        $sql .= ' LEFT JOIN acl_security_identities s ON (s.id = e.security_identity_id) ';

        return $sql;
    }
}
