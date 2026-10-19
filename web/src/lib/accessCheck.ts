// accessHeadline reads the two directions of an access check (VLAN plan M3)
// as one answer: both ways, only from the first side, only from the second,
// neither, or partly. The key picks firewall:accessCheck.headline.<key>.
export type AccessHeadline = 'both' | 'fromOnly' | 'toOnly' | 'none' | 'partial'

export function accessHeadline(forward: string, reverse: string): AccessHeadline {
  if (forward === 'partial' || reverse === 'partial') return 'partial'
  if (forward === 'allow') return reverse === 'allow' ? 'both' : 'fromOnly'
  return reverse === 'allow' ? 'toOnly' : 'none'
}
